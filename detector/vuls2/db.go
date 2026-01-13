package vuls2

import (
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"

	"github.com/MaineK00n/vuls2/pkg/db/fetch"
	"github.com/MaineK00n/vuls2/pkg/db/session"
)

var (
	// DefaultPath is the path for vuls2 db file
	DefaultPath = func() string {
		wd, _ := os.Getwd()
		return filepath.Join(wd, "vuls.db")
	}()
)

func newDBConfig(vuls2Conf config.Vuls2Conf, noProgress bool) (*session.Config, error) {
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

	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    vuls2Conf.Path,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		return nil, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := sesh.Storage().Open(); err != nil {
		return nil, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return nil, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil {
		return nil, xerrors.Errorf("unexpected vuls2 db metadata. metadata: nil, path: %s", vuls2Conf.Path)
	}
	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		return nil, xerrors.Errorf("Failed to get schema version. err: %w", err)
	}
	if metadata.SchemaVersion != sv {
		return nil, xerrors.Errorf("vuls2 db schema version mismatch. expected: %d, actual: %d", session.SchemaVersion, metadata.SchemaVersion)
	}

	return &session.Config{
		Type:      "boltdb",
		Path:      vuls2Conf.Path,
		Options:   session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
		WithCache: true,
	}, nil
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

	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    vuls2Conf.Path,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		return false, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := sesh.Storage().Open(); err != nil {
		return false, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return false, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil {
		return false, xerrors.Errorf("unexpected vuls2 db metadata. metadata: nil, path: %s", vuls2Conf.Path)
	}

	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		return false, xerrors.Errorf("Failed to get schema version. err: %w", err)
	}

	if metadata.SchemaVersion != sv {
		if vuls2Conf.SkipUpdate {
			return false, xerrors.Errorf("vuls2 db schema version mismatch. expected: %d, actual: %d", sv, metadata.SchemaVersion)
		}
		return true, nil
	}

	if vuls2Conf.SkipUpdate {
		return false, nil
	}

	if metadata.Downloaded != nil && now.Before((*metadata.Downloaded).Add(1*time.Hour)) {
		return false, nil
	}
	return metadata.LastModified.Add(6 * time.Hour).Before(now), nil
}
