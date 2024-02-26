//go:build !scanner
// +build !scanner

package detector

import (
	"context"
	"slices"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/db"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/log"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// DetectLibsCves fills LibraryScanner information
func DetectLibsCves(r *models.ScanResult, trivyOpts config.TrivyOpts, logOpts logging.LogOpts, noProgress bool) (err error) {
	totalCnt := 0
	if len(r.LibraryScanners) == 0 {
		return
	}

	// initialize trivy's logger and db
	err = log.InitLogger(logOpts.Debug, logOpts.Quiet)
	if err != nil {
		return err
	}

	logging.Log.Info("Updating library db...")
	if err := downloadDB("", trivyOpts, noProgress, false); err != nil {
		return err
	}
	if err := trivydb.Init(trivyOpts.TrivyCacheDBDir); err != nil {
		return err
	}
	defer trivydb.Close()

	var javaDBClient *javadb.DB
	if slices.ContainsFunc(r.LibraryScanners, func(s models.LibraryScanner) bool { return s.Type == ftypes.Jar }) {
		if err := downloadJavaDB(trivyOpts, noProgress); err != nil {
			return err
		}
		javaDBClient, err = newJavaDBClient()
		if err != nil {
			return err
		}
	}

	for _, lib := range r.LibraryScanners {
		vinfos, err := lib.Scan(javaDBClient)
		if err != nil {
			return err
		}
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
	cacheDir := trivyOpts.TrivyCacheDBDir
	client := db.NewClient(cacheDir, noProgress)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		logging.Log.Info("Need to update DB")
		logging.Log.Info("Downloading DB...")
		if err := client.Download(ctx, cacheDir, ftypes.RegistryOptions{}); err != nil {
			return xerrors.Errorf("Failed to download vulnerability DB. err: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(cacheDir); err != nil {
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
	log.Logger.Debugf("DB Schema: %d, UpdatedAt: %s, NextUpdate: %s, DownloadedAt: %s",
		meta.Version, meta.UpdatedAt, meta.NextUpdate, meta.DownloadedAt)
	return nil
}

func downloadJavaDB(trivyOpts config.TrivyOpts, noProgress bool) error {
	javadb.Init(trivyOpts.TrivyCacheDBDir, trivyOpts.TrivyJavaDBRepository, trivyOpts.TrivySkipJavaDBUpdate, noProgress, ftypes.RegistryOptions{})
	if err := javadb.Update(); err != nil {
		return xerrors.Errorf("Failed to download trivy Java DB. err: %w", err)
	}
	return nil
}

func newJavaDBClient() (*javadb.DB, error) {
	client, err := javadb.NewClient()
	if err != nil {
		return nil, xerrors.Errorf("Failed to open trivy Java DB. err: %w", err)
	}
	return client, nil
}
