//go:build !scanner
// +build !scanner

package detector

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	trivydbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/javadb"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

type libraryDetector struct {
	scanner      models.LibraryScanner
	javaDBClient *javadb.DBClient
}

// DetectLibsCves fills LibraryScanner information
func DetectLibsCves(r *models.ScanResult, trivyOpts config.TrivyOpts, logOpts logging.LogOpts, noProgress bool) (err error) {
	totalCnt := 0
	if len(r.LibraryScanners) == 0 {
		return
	}

	// initialize trivy's logger and db
	err = log.InitLogger(logOpts.Debug, logOpts.Quiet)
	if err != nil {
		return xerrors.Errorf("Failed to init trivy logger. err: %w", err)
	}

	logging.Log.Info("Updating library db...")
	if err := downloadDB("", trivyOpts, noProgress, false); err != nil {
		return xerrors.Errorf("Failed to download trivy DB. err: %w", err)
	}
	if err := trivydb.Init(trivyOpts.TrivyCacheDBDir); err != nil {
		return xerrors.Errorf("Failed to init trivy DB. err: %w", err)
	}
	defer trivydb.Close()

	var javaDBClient *javadb.DBClient
	defer javaDBClient.Close()
	for i, lib := range r.LibraryScanners {
		d := libraryDetector{scanner: lib}
		if lib.Type == ftypes.Jar {
			if javaDBClient == nil {
				if err := javadb.UpdateJavaDB(trivyOpts, noProgress); err != nil {
					return xerrors.Errorf("Failed to update Trivy Java DB. err: %w", err)
				}

				javaDBClient, err = javadb.NewClient(trivyOpts.TrivyCacheDBDir)
				if err != nil {
					return xerrors.Errorf("Failed to open Trivy Java DB. err: %w", err)
				}
			}
			d.javaDBClient = javaDBClient
		}

		vinfos, err := d.scan()
		if err != nil {
			return xerrors.Errorf("Failed to scan library. err: %w", err)
		}
		r.LibraryScanners[i] = d.scanner
		
		for _, vinfo := range vinfos {
			vinfo.Confidences.AppendIfMissing(models.TrivyMatch)
			if v, ok := r.ScannedCves[vinfo.CveID]; !ok {
				r.ScannedCves[vinfo.CveID] = vinfo
			} else {
				v.LibraryFixedIns = append(v.LibraryFixedIns, vinfo.LibraryFixedIns...)
				r.ScannedCves[vinfo.CveID] = v
			}
		}
		totalCnt += len(vinfos)
	}

	logging.Log.Infof("%s: %d CVEs are detected with Library",
		r.FormatServerName(), totalCnt)

	return nil
}

func downloadDB(appVersion string, trivyOpts config.TrivyOpts, noProgress, skipUpdate bool) error {
	client := db.NewClient(trivyOpts.TrivyCacheDBDir, noProgress)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		logging.Log.Info("Need to update DB")
		logging.Log.Info("Downloading DB...")
		if err := client.Download(ctx, trivyOpts.TrivyCacheDBDir, ftypes.RegistryOptions{}); err != nil {
			return xerrors.Errorf("Failed to download vulnerability DB. err: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(trivyOpts.TrivyCacheDBDir); err != nil {
		return xerrors.Errorf("Failed to show database info. err: %w", err)
	}
	return nil
}

func showDBInfo(cacheDir string) error {
	m := metadata.NewClient(cacheDir)
	meta, err := m.Get()
	if err != nil {
		return xerrors.Errorf("Failed to get DB metadata. err: %w", err)
	}
	logging.Log.Debugf("DB Schema: %d, UpdatedAt: %s, NextUpdate: %s, DownloadedAt: %s",
		meta.Version, meta.UpdatedAt, meta.NextUpdate, meta.DownloadedAt)
	return nil
}

// Scan : scan target library
func (d *libraryDetector) scan() ([]models.VulnInfo, error) {
	if d.scanner.Type == ftypes.Jar {
		if err := d.improveJARInfo(); err != nil {
			return nil, xerrors.Errorf("Failed to improve JAR information by trivy Java DB. err: %w", err)
		}
	}
	scanner, ok := library.NewDriver(d.scanner.Type)
	if !ok {
		return nil, xerrors.Errorf("Failed to new a library driver for %s", d.scanner.Type)
	}
	var vulnerabilities = []models.VulnInfo{}
	for _, pkg := range d.scanner.Libs {
		tvulns, err := scanner.DetectVulnerabilities("", pkg.Name, pkg.Version)
		if err != nil {
			return nil, xerrors.Errorf("Failed to detect %s vulnerabilities. err: %w", scanner.Type(), err)
		}
		if len(tvulns) == 0 {
			continue
		}

		vulns := d.convertFanalToVuln(tvulns)
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

func (d *libraryDetector) improveJARInfo() error {
	libs := make([]models.Library, 0, len(d.scanner.Libs))
	for _, l := range d.scanner.Libs {
		if l.Digest == "" {
			// This is the case from pom.properties, it should be respected as is.
			libs = append(libs, l)
			continue
		}

		algorithm, sha1, found := strings.Cut(l.Digest, ":")
		if !found || algorithm != "sha1" {
			logging.Log.Debugf("No SHA1 hash found for %s in the digest: %q", l.FilePath, l.Digest)
			libs = append(libs, l)
			continue
		}

		foundProps, err := d.javaDBClient.SearchBySHA1(sha1)
		if err != nil {
			if !errors.Is(err, jar.ArtifactNotFoundErr) {
				return xerrors.Errorf("Failed to search trivy Java DB. err: %w", err)
			}

			logging.Log.Debugf("No record in Java DB for %s by SHA1: %s", l.FilePath, sha1)
			libs = append(libs, l)
			continue
		}

		foundLib := foundProps.Library()
		l.Name = foundLib.Name
		l.Version = foundLib.Version
		libs = append(libs, l)
	}

	d.scanner.Libs = lo.UniqBy(libs, func(lib models.Library) string {
		return fmt.Sprintf("%s::%s::%s", lib.Name, lib.Version, lib.FilePath)
	})
	return nil
}

func (d libraryDetector) convertFanalToVuln(tvulns []types.DetectedVulnerability) (vulns []models.VulnInfo) {
	for _, tvuln := range tvulns {
		vinfo, err := d.getVulnDetail(tvuln)
		if err != nil {
			logging.Log.Debugf("failed to getVulnDetail. err: %+v, tvuln: %#v", err, tvuln)
			continue
		}
		vulns = append(vulns, vinfo)
	}
	return vulns
}

func (d libraryDetector) getVulnDetail(tvuln types.DetectedVulnerability) (vinfo models.VulnInfo, err error) {
	vul, err := trivydb.Config{}.GetVulnerability(tvuln.VulnerabilityID)
	if err != nil {
		return vinfo, err
	}

	vinfo.CveID = tvuln.VulnerabilityID
	vinfo.CveContents = getCveContents(tvuln.VulnerabilityID, vul)
	vinfo.LibraryFixedIns = []models.LibraryFixedIn{
		{
			Key:     d.scanner.GetLibraryKey(),
			Name:    tvuln.PkgName,
			FixedIn: tvuln.FixedVersion,
			Path:    d.scanner.LockfilePath,
		},
	}
	return vinfo, nil
}

func getCveContents(cveID string, vul trivydbTypes.Vulnerability) (contents map[models.CveContentType][]models.CveContent) {
	contents = map[models.CveContentType][]models.CveContent{}
	refs := []models.Reference{}
	for _, refURL := range vul.References {
		refs = append(refs, models.Reference{Source: "trivy", Link: refURL})
	}

	contents[models.Trivy] = []models.CveContent{
		{
			Type:          models.Trivy,
			CveID:         cveID,
			Title:         vul.Title,
			Summary:       vul.Description,
			Cvss3Severity: string(vul.Severity),
			References:    refs,
		},
	}
	return contents
}
