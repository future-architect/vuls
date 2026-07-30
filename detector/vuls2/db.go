package vuls2

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/pkg/errors"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/xerrors"
	"oras.land/oras-go/v2/registry/remote"

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

// newDBConfig downloads or refreshes the db if due, validates its schema
// version, and returns the session config to open it with.
//
// withCache decides whether the returned session carries a read cache. The
// cache is unbounded (a sync.Map that never evicts), so it is only safe for a
// session whose lifetime is bounded: a report run holds one per server and
// drops it afterwards, which is what makes the cache pay off there. A session
// that lives as long as a server process (see SharedDB) must not carry one, or
// it accumulates every advisory and vulnerability it ever read until the
// process is OOM-killed.
func newDBConfig(vuls2Conf config.Vuls2Conf, noProgress, withCache bool) (*session.Config, error) {
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
		WithCache: withCache,
	}, nil
}

// hasNewerRemote reports whether the repository holds a db other than the one on
// disk, comparing the manifest digest that fetch recorded in the local db's
// metadata against the digest the repository's reference resolves to now.
//
// shouldDownload can only tell that the local db is old enough to be worth
// checking: it goes by timestamps, and the nightly db's LastModified is the
// night it was built, so a db past the staleness window looks due on every
// check until something replaces it. Downloading on that alone re-fetches
// gigabytes on every check even when the tag has not moved. Resolving the
// manifest costs one request, so it is worth asking before spending a download.
func hasNewerRemote(ctx context.Context, vuls2Conf config.Vuls2Conf) (bool, error) {
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
	if metadata == nil || metadata.Digest == nil {
		// A db that was built locally rather than fetched carries no digest, so
		// there is nothing to compare it by and the repository's db counts as
		// the newer one.
		return true, nil
	}

	repo, err := remote.NewRepository(vuls2Conf.Repository)
	if err != nil {
		return false, xerrors.Errorf("Failed to create client for %s. err: %w", vuls2Conf.Repository, err)
	}
	if repo.Reference.Reference == "" {
		return false, xerrors.Errorf("unexpected repository format. expected: %q, actual: %q", []string{"<repository>@<digest>", "<repository>:<tag>", "<repository>:<tag>@<digest>"}, vuls2Conf.Repository)
	}

	desc, err := repo.Resolve(ctx, repo.Reference.Reference)
	if err != nil {
		return false, xerrors.Errorf("Failed to resolve %s. err: %w", vuls2Conf.Repository, err)
	}

	return desc.Digest.String() != *metadata.Digest, nil
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
