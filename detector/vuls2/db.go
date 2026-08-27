package vuls2

import (
	"fmt"
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

	bgFetch backgroundFetch
)

// backgroundFetch coordinates asynchronous DB downloads so that at most one
// fetch runs at a time. When a request determines the DB is stale it triggers
// a background goroutine and immediately falls through to use the current
// (stale) DB. Subsequent requests that arrive while the fetch is in flight
// skip the download entirely.
//
// It also tracks whether the initial startup fetch has completed, allowing
// the server's /health and /vuls endpoints to report readiness.
type backgroundFetch struct {
	mu          sync.Mutex
	downloading bool

	// initialDone is closed once the startup fetch completes (success or
	// failure). A nil channel means no startup fetch was requested.
	initialDone chan struct{}
	initialErr  error
}

func newDBConfig(vuls2Conf config.Vuls2Conf, noProgress bool) (*session.Config, error) {
	willDownload, err := shouldDownload(vuls2Conf, time.Now())
	if err != nil {
		return nil, xerrors.Errorf("Failed to check whether to download vuls2 db. err: %w", err)
	}

	if willDownload {
		syncRequired, err := mustFetchSync(vuls2Conf.Path)
		if err != nil {
			return nil, xerrors.Errorf("Failed to check db state. err: %w", err)
		}

		if syncRequired {
			// DB does not exist or has incompatible schema — must download synchronously.
			logging.Log.Infof("Fetching vuls2 db (sync). repository: %s", vuls2Conf.Repository)
			if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
				return nil, xerrors.Errorf("Failed to fetch vuls2 db. err: %w", err)
			}
		} else {
			// DB exists with correct schema but is stale — trigger a background
			// refresh and continue with the current version.
			bgFetch.triggerAsync(vuls2Conf, noProgress)
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

// mustFetchSync returns true when the DB cannot be used as-is and a
// synchronous download is required: either the file does not exist, or it
// exists but its schema version does not match the expected one.
func mustFetchSync(dbpath string) (bool, error) {
	if _, err := os.Stat(dbpath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, xerrors.Errorf("Failed to stat db. err: %w", err)
	}

	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		return false, xerrors.Errorf("Failed to get schema version. err: %w", err)
	}

	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    dbpath,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		return true, nil
	}
	if err := sesh.Storage().Open(); err != nil {
		return true, nil
	}
	defer sesh.Storage().Close()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil || metadata == nil {
		return true, nil
	}

	return metadata.SchemaVersion != sv, nil
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

// triggerAsync starts a background fetch if no download is already in progress.
// It returns immediately in all cases — the caller continues with the current DB.
func (bf *backgroundFetch) triggerAsync(vuls2Conf config.Vuls2Conf, noProgress bool) {
	bf.mu.Lock()
	if bf.downloading {
		bf.mu.Unlock()
		logging.Log.Infof("vuls2 db download already in progress, using current db")
		return
	}
	bf.downloading = true
	bf.mu.Unlock()

	logging.Log.Infof("Fetching vuls2 db in background. repository: %s", vuls2Conf.Repository)
	go func() {
		defer func() {
			bf.mu.Lock()
			bf.downloading = false
			bf.mu.Unlock()
		}()

		if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
			logging.Log.Warnf("Background vuls2 db fetch failed: %+v", err)
		} else {
			logging.Log.Infof("Background vuls2 db fetch completed successfully")
		}
	}()
}

// StartInitialFetch triggers a one-time background download of the vuls2 DB at
// server startup. It fills in the default repository/path just like openSession
// does. The /health endpoint reports 503 until the download finishes. If the DB
// already exists with a valid schema, the initial fetch is considered done
// immediately and a normal background refresh is triggered instead.
func StartInitialFetch(vuls2Conf config.Vuls2Conf, noProgress bool) {
	if vuls2Conf.Repository == "" {
		sv, err := session.SchemaVersion("boltdb")
		if err != nil {
			logging.Log.Warnf("StartInitialFetch: failed to get schema version: %+v", err)
			return
		}
		vuls2Conf.Repository = fmt.Sprintf("%s:%d", defaultRegistory, sv)
	}
	if vuls2Conf.Path == "" {
		vuls2Conf.Path = DefaultPath
	}

	syncRequired, err := mustFetchSync(vuls2Conf.Path)
	if err != nil {
		logging.Log.Warnf("StartInitialFetch: failed to check db state: %+v", err)
		return
	}

	if !syncRequired {
		// DB already usable — mark ready immediately, trigger a background
		// refresh for staleness (same as a normal request would).
		bgFetch.mu.Lock()
		bgFetch.initialDone = make(chan struct{})
		close(bgFetch.initialDone)
		bgFetch.mu.Unlock()

		willDownload, _ := shouldDownload(vuls2Conf, time.Now())
		if willDownload {
			bgFetch.triggerAsync(vuls2Conf, noProgress)
		}
		return
	}

	// DB doesn't exist or schema mismatch — download in background and mark
	// not-ready until complete.
	bgFetch.mu.Lock()
	bgFetch.initialDone = make(chan struct{})
	bgFetch.downloading = true
	bgFetch.mu.Unlock()

	logging.Log.Infof("Starting initial vuls2 db download. repository: %s", vuls2Conf.Repository)
	go func() {
		defer func() {
			bgFetch.mu.Lock()
			bgFetch.downloading = false
			close(bgFetch.initialDone)
			bgFetch.mu.Unlock()
		}()

		if err := fetch.Fetch(fetch.WithRepository(vuls2Conf.Repository), fetch.WithDBPath(vuls2Conf.Path), fetch.WithNoProgress(noProgress)); err != nil {
			logging.Log.Errorf("Initial vuls2 db fetch failed: %+v", err)
			bgFetch.mu.Lock()
			bgFetch.initialErr = err
			bgFetch.mu.Unlock()
		} else {
			logging.Log.Infof("Initial vuls2 db fetch completed successfully")
		}
	}()
}

// Ready reports whether the vuls2 DB is available for serving requests.
// It returns false with a descriptive message while the initial startup
// download is still in progress.
func Ready() (ok bool, msg string) {
	bgFetch.mu.Lock()
	done := bgFetch.initialDone
	bgFetch.mu.Unlock()

	if done == nil {
		// No startup fetch was requested (e.g. skipUpdate or not configured).
		return true, "ok"
	}

	select {
	case <-done:
		bgFetch.mu.Lock()
		err := bgFetch.initialErr
		bgFetch.mu.Unlock()
		if err != nil {
			return false, fmt.Sprintf("initial vuls2 db fetch failed: %v", err)
		}
		return true, "ok"
	default:
		return false, "downloading vuls2"
	}
}

// Downloading reports whether a background fetch is currently in progress.
func Downloading() bool {
	bgFetch.mu.Lock()
	defer bgFetch.mu.Unlock()
	return bgFetch.downloading
}
