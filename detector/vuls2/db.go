package vuls2

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	db "github.com/MaineK00n/vuls2/pkg/db/common"
	"github.com/MaineK00n/vuls2/pkg/db/fetch"
)

var (
	// DefaultGHCRRepository is GitHub Container Registry for vuls2 db
	DefaultGHCRRepository = fmt.Sprintf("%s:%d", "ghcr.io/vulsio/vuls-nightly-db", db.SchemaVersion)

	// DefaultPath is the path for vuls2 db file
	DefaultPath = func() string {
		wd, _ := os.Getwd()
		return filepath.Join(wd, "vuls.db")
	}()
)

func newDBConnection(vuls2Conf config.Vuls2Conf, noProgress bool) (db.DB, error) {
	willDownload, err := shouldDownload(vuls2Conf, time.Now())
	if err != nil {
		return nil, xerrors.Errorf("Failed to check whether to download vuls2 db. err: %w", err)
	}

	if willDownload {
		logging.Log.Infof("Fetching vuls2 db. repository: %s", vuls2Conf.Repository)
		if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
			return nil, xerrors.Errorf("Failed to fetch vuls2 db. err: %w", err)
		}
	}

	dbc, err := (&db.Config{
		Type: "boltdb",
		Path: vuls2Conf.Path,
	}).New()
	if err != nil {
		return nil, xerrors.Errorf("Failed to new vuls2 db connection. err: %w", err)
	}

	return dbc, nil
}

func shouldDownload(vuls2Conf config.Vuls2Conf, now time.Time) (bool, error) {
	if _, err := os.Stat(vuls2Conf.Path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if vuls2Conf.SkipUpdate {
				return false, xerrors.Errorf("%s not found, cannot skip update", vuls2Conf.Path)
			}
			return true, nil
		}
		return false, xerrors.Errorf("Failed to stat vuls2 db file. err: %w", err)
	}

	if vuls2Conf.SkipUpdate {
		return false, nil
	}

	dbc, err := (&db.Config{
		Type: "boltdb",
		Path: vuls2Conf.Path,
	}).New()
	if err != nil {
		return false, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := dbc.Open(); err != nil {
		return false, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}
	defer dbc.Close()

	metadata, err := dbc.GetMetadata()
	if err != nil {
		return false, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil {
		return false, xerrors.Errorf("Unexpected Vuls2 db metadata. metadata: nil,. path: %s", vuls2Conf.Path)
	}

	if metadata.Downloaded != nil && now.Before((*metadata.Downloaded).Add(1*time.Hour)) {
		return false, nil
	}
	return metadata.LastModified.Add(6 * time.Hour).Before(now), nil
}
