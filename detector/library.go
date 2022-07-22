//go:build !scanner
// +build !scanner

package detector

import (
	"context"

	trivydb "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// DetectLibsCves fills LibraryScanner information
func DetectLibsCves(r *models.ScanResult, cacheDir string, noProgress bool) (err error) {
	totalCnt := 0
	if len(r.LibraryScanners) == 0 {
		return
	}

	// initialize trivy's logger and db
	err = log.InitLogger(false, false)
	if err != nil {
		return err
	}

	logging.Log.Info("Updating library db...")
	if err := downloadDB("", cacheDir, noProgress, false); err != nil {
		return err
	}

	if err := trivydb.Init(cacheDir); err != nil {
		return err
	}
	defer trivydb.Close()

	for _, lib := range r.LibraryScanners {
		vinfos, err := lib.Scan()
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

func downloadDB(appVersion, cacheDir string, quiet, skipUpdate bool) error {
	client := db.NewClient(cacheDir, quiet, false)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(appVersion, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		logging.Log.Info("Need to update DB")
		logging.Log.Info("Downloading DB...")
		if err := client.Download(ctx, cacheDir); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(cacheDir); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func showDBInfo(cacheDir string) error {
	m := metadata.NewClient(cacheDir)
	meta, err := m.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	log.Logger.Debugf("DB Schema: %d, UpdatedAt: %s, NextUpdate: %s, DownloadedAt: %s",
		meta.Version, meta.UpdatedAt, meta.NextUpdate, meta.DownloadedAt)
	return nil
}
