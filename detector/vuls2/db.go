package vuls2

import (
	"os"
	"path/filepath"
	"sync"
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

var (
	sessionMu     sync.Mutex
	cachedSession *session.Session
	cachedPath    string
)

// getSession returns a shared, opened vuls2 db session. The session is opened
// lazily on the first call and reused by subsequent callers so that concurrent
// users (e.g. `vuls server` handling parallel HTTP requests) do not repeatedly
// invoke bolt.Open(), which would otherwise serialize on BoltDB's OS-level file
// lock and cause severe latency under load.
//
// CloseSession should be called at process shutdown to release the file handle.
func getSession(vuls2Conf config.Vuls2Conf, noProgress bool) (*session.Session, error) {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if cachedSession != nil && cachedPath == vuls2Conf.Path {
		return cachedSession, nil
	}

	if cachedSession != nil {
		_ = cachedSession.Storage().Close()
		cachedSession.Cache().Close()
		cachedSession = nil
		cachedPath = ""
	}

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
		Type:      "boltdb",
		Path:      vuls2Conf.Path,
		Options:   session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
		WithCache: true,
	}).New()
	if err != nil {
		return nil, xerrors.Errorf("Failed to new vuls2 db connection. path: %s, err: %w", vuls2Conf.Path, err)
	}

	if err := sesh.Storage().Open(); err != nil {
		sesh.Cache().Close()
		return nil, xerrors.Errorf("Failed to open vuls2 db. path: %s, err: %w", vuls2Conf.Path, err)
	}

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		_ = sesh.Storage().Close()
		sesh.Cache().Close()
		return nil, xerrors.Errorf("Failed to get vuls2 db metadata. path: %s, err: %w", vuls2Conf.Path, err)
	}
	if metadata == nil {
		_ = sesh.Storage().Close()
		sesh.Cache().Close()
		return nil, xerrors.Errorf("unexpected vuls2 db metadata. metadata: nil, path: %s", vuls2Conf.Path)
	}
	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		_ = sesh.Storage().Close()
		sesh.Cache().Close()
		return nil, xerrors.Errorf("Failed to get schema version. err: %w", err)
	}
	if metadata.SchemaVersion != sv {
		_ = sesh.Storage().Close()
		sesh.Cache().Close()
		return nil, xerrors.Errorf("vuls2 db schema version mismatch. expected: %d, actual: %d", sv, metadata.SchemaVersion)
	}

	cachedSession = sesh
	cachedPath = vuls2Conf.Path
	return sesh, nil
}

// CloseSession releases the cached vuls2 db session. Safe to call when no
// session has ever been opened, and idempotent across repeated calls.
// Intended to be deferred at process shutdown (e.g. `vuls server`).
func CloseSession() error {
	sessionMu.Lock()
	defer sessionMu.Unlock()

	if cachedSession == nil {
		return nil
	}
	sesh := cachedSession
	cachedSession = nil
	cachedPath = ""

	if err := sesh.Storage().Close(); err != nil {
		sesh.Cache().Close()
		return xerrors.Errorf("Failed to close vuls2 db storage. err: %w", err)
	}
	sesh.Cache().Close()
	return nil
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
