package libmanager

import (
	"context"

	db2 "github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/github"
	"github.com/aquasecurity/trivy/pkg/indicator"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// FillLibrary fills LibraryScanner informations
func FillLibrary(r *models.ScanResult) (totalCnt int, err error) {
	if len(r.LibraryScanners) == 0 {
		return
	}

	// initialize trivy's logger and db
	err = log.InitLogger(false, false)
	if err != nil {
		return 0, err
	}

	util.Log.Info("Updating library db...")
	if err := downloadDB(config.Version, config.Conf.TrivyCacheDBDir, config.Conf.NoProgress, false, false); err != nil {
		return 0, err
	}

	if err := db2.Init(config.Conf.TrivyCacheDBDir); err != nil {
		return 0, err
	}
	defer db2.Close()

	for _, lib := range r.LibraryScanners {
		vinfos, err := lib.Scan()
		if err != nil {
			return 0, err
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

	return totalCnt, nil
}

func downloadDB(appVersion, cacheDir string, quiet, light, skipUpdate bool) error {
	client := initializeDBClient(cacheDir, quiet)
	ctx := context.Background()
	needsUpdate, err := client.NeedsUpdate(appVersion, light, skipUpdate)
	if err != nil {
		return xerrors.Errorf("database error: %w", err)
	}

	if needsUpdate {
		util.Log.Info("Need to update DB")
		util.Log.Info("Downloading DB...")
		if err := client.Download(ctx, cacheDir, light); err != nil {
			return xerrors.Errorf("failed to download vulnerability DB: %w", err)
		}
		if err = client.UpdateMetadata(cacheDir); err != nil {
			return xerrors.Errorf("unable to update database metadata: %w", err)
		}
	}

	// for debug
	if err := showDBInfo(cacheDir); err != nil {
		return xerrors.Errorf("failed to show database info: %w", err)
	}
	return nil
}

func initializeDBClient(cacheDir string, quiet bool) db.Client {
	config := db2.Config{}
	client := github.NewClient()
	progressBar := indicator.NewProgressBar(quiet)
	realClock := clock.RealClock{}
	fs := afero.NewOsFs()
	metadata := db.NewMetadata(fs, cacheDir)
	dbClient := db.NewClient(config, client, progressBar, realClock, metadata)
	return dbClient
}

func showDBInfo(cacheDir string) error {
	m := db.NewMetadata(afero.NewOsFs(), cacheDir)
	metadata, err := m.Get()
	if err != nil {
		return xerrors.Errorf("something wrong with DB: %w", err)
	}
	util.Log.Debugf("DB Schema: %d, Type: %d, UpdatedAt: %s, NextUpdate: %s",
		metadata.Version, metadata.Type, metadata.UpdatedAt, metadata.NextUpdate)
	return nil
}
