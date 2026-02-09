//go:build !scanner

package detector

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	trivydbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/detector/library"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/javadb"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// DefaultTrivyDBRepositories is the official repositories of Trivy DB
var DefaultTrivyDBRepositories = []string{db.DefaultGCRRepository, db.DefaultGHCRRepository}

type libraryDetector struct {
	scanner               models.LibraryScanner
	javaDBClient          *javadb.DBClient
	detectDevDependencies bool
}

// DetectLibsCves fills LibraryScanner information
func DetectLibsCves(r *models.ScanResult, trivyOpts config.TrivyOpts, logOpts logging.LogOpts, noProgress bool) (err error) {
	totalCnt := 0
	if len(r.LibraryScanners) == 0 {
		return
	}

	// initialize trivy's logger and db
	log.InitLogger(logOpts.Debug, logOpts.Quiet)

	logging.Log.Info("Updating library db...")
	if err := downloadDB("", trivyOpts, noProgress, false); err != nil {
		return xerrors.Errorf("Failed to download trivy DB. err: %w", err)
	}
	if err := trivydb.Init(filepath.Join(trivyOpts.TrivyCacheDBDir, "db")); err != nil {
		return xerrors.Errorf("Failed to init trivy DB. err: %w", err)
	}
	defer trivydb.Close()

	var javaDBClient *javadb.DBClient
	defer javaDBClient.Close()
	for i, lib := range r.LibraryScanners {
		d := libraryDetector{
			scanner:               lib,
			detectDevDependencies: slices.Contains(trivyOpts.DetectDevLockfilePaths, lib.LockfilePath),
		}
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
	if len(trivyOpts.TrivyDBRepositories) == 0 {
		trivyOpts.TrivyDBRepositories = DefaultTrivyDBRepositories
	}
	refs := make([]name.Reference, 0, len(trivyOpts.TrivyDBRepositories))
	for _, repo := range trivyOpts.TrivyDBRepositories {
		ref, err := func() (name.Reference, error) {
			ref, err := name.ParseReference(repo, name.WithDefaultTag(""))
			if err != nil {
				return nil, err
			}

			// Add the schema version if the tag is not specified for backward compatibility.
			t, ok := ref.(name.Tag)
			if !ok || t.TagStr() != "" {
				return ref, nil
			}

			ref = t.Tag(fmt.Sprint(trivydb.SchemaVersion))
			logging.Log.Infof("Adding schema version to the DB repository for backward compatibility. repository: %s", ref.String())

			return ref, nil
		}()
		if err != nil {
			return xerrors.Errorf("invalid db repository: %w", err)
		}
		refs = append(refs, ref)
	}
	client := db.NewClient(filepath.Join(trivyOpts.TrivyCacheDBDir, "db"), noProgress, db.WithDBRepository(refs))
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(ctx, appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("Failed to check NeedsUpdate. err: %w", err)
	}

	if needsUpdate {
		logging.Log.Info("Need to update DB")
		logging.Log.Infof("Downloading DB from %s...", strings.Join(trivyOpts.TrivyDBRepositories, ", "))
		if err := client.Download(ctx, filepath.Join(trivyOpts.TrivyCacheDBDir, "db"), ftypes.RegistryOptions{}); err != nil {
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
	m := metadata.NewClient(filepath.Join(cacheDir, "db"))
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
		if pkg.Dev && !d.detectDevDependencies {
			continue
		}

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

		foundLib := foundProps.Package()
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
			Version: tvuln.InstalledVersion,
			FixedIn: tvuln.FixedVersion,
			Path:    d.scanner.LockfilePath,
		},
	}
	return vinfo, nil
}

func getCveContents(cveID string, vul trivydbTypes.Vulnerability) (contents map[models.CveContentType][]models.CveContent) {
	contents = map[models.CveContentType][]models.CveContent{}
	refs := make([]models.Reference, 0, len(vul.References))
	for _, refURL := range vul.References {
		refs = append(refs, models.Reference{Source: "trivy", Link: refURL})
	}

	for source, severity := range vul.VendorSeverity {
		contents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))] = append(contents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))], models.CveContent{
			Type:          models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source)),
			CveID:         cveID,
			Title:         vul.Title,
			Summary:       vul.Description,
			Cvss3Severity: trivydbTypes.SeverityNames[severity],
			Published: func() time.Time {
				if vul.PublishedDate != nil {
					return *vul.PublishedDate
				}
				return time.Time{}
			}(),
			LastModified: func() time.Time {
				if vul.LastModifiedDate != nil {
					return *vul.LastModifiedDate
				}
				return time.Time{}
			}(),
			References: refs,
		})
	}

	for source, cvss := range vul.CVSS {
		contents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))] = append(contents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))], models.CveContent{
			Type:         models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source)),
			CveID:        cveID,
			Title:        vul.Title,
			Summary:      vul.Description,
			Cvss2Score:   cvss.V2Score,
			Cvss2Vector:  cvss.V2Vector,
			Cvss3Score:   cvss.V3Score,
			Cvss3Vector:  cvss.V3Vector,
			Cvss40Score:  cvss.V40Score,
			Cvss40Vector: cvss.V40Vector,
			Published: func() time.Time {
				if vul.PublishedDate != nil {
					return *vul.PublishedDate
				}
				return time.Time{}
			}(),
			LastModified: func() time.Time {
				if vul.LastModifiedDate != nil {
					return *vul.LastModifiedDate
				}
				return time.Time{}
			}(),
			References: refs,
		})
	}

	return contents
}
