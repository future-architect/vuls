package vuls2_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/db/session/types"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/vuls2"
)

// newFixtureDB writes a db carrying digest as its metadata and returns its path,
// so a test can tell two generations apart.
func newFixtureDB(t *testing.T, digest string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "vuls.db")
	if err := putMetadata(types.Metadata{
		LastModified:  *parse("2024-01-02T00:00:00Z"),
		Downloaded:    parse("2024-01-02T00:00:00Z"),
		SchemaVersion: schemaVersionBoltDB(t),
		Digest:        &digest,
	}, path); err != nil {
		t.Fatalf("putMetadata() err = %v", err)
	}
	return path
}

// openFixtureDB opens path read-only, the way SharedDB opens a db it installs.
func openFixtureDB(t *testing.T, path string) *session.Session {
	t.Helper()

	sesh, err := (&session.Config{
		Type:    "boltdb",
		Path:    path,
		Options: session.StorageOptions{BoltDB: &bolt.Options{ReadOnly: true}},
	}).New()
	if err != nil {
		t.Fatalf("session.Config.New() err = %v", err)
	}
	if err := sesh.Storage().Open(); err != nil {
		t.Fatalf("Storage().Open() err = %v", err)
	}
	return sesh
}

// digestOf reads the db through sesh, which doubles as an is-it-still-open
// check: a closed bolt db fails the read instead of serving it.
func digestOf(t *testing.T, sesh *session.Session) (string, error) {
	t.Helper()

	metadata, err := sesh.Storage().GetMetadata()
	if err != nil {
		return "", err
	}
	if metadata == nil || metadata.Digest == nil {
		t.Fatalf("GetMetadata() digest = nil, want a digest")
	}
	return *metadata.Digest, nil
}

func TestSharedDB_AcquireBeforeReady(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}

	// A db on disk is not a db this process has open: until Reload installs one,
	// a request has to be refused rather than made to open (or fetch) it.
	if d.Ready() {
		t.Errorf("Ready() = true before Reload, want false")
	}
	if _, _, err := d.Acquire(); err == nil {
		t.Errorf("Acquire() err = nil before Reload, want an error")
	}
}

func TestSharedDB_OpenLocal(t *testing.T) {
	// SkipUpdate is deliberately false and the fixture's LastModified is old
	// enough that a refresh is due, so a fetch would be attempted if OpenLocal
	// honoured the staleness rule. It must not: a db that is merely stale is
	// still one worth serving while the refresher catches up, and this test
	// would have to reach the registry otherwise.
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a")}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.OpenLocal(); err != nil {
		t.Fatalf("OpenLocal() err = %v", err)
	}
	defer d.Close()

	if !d.Ready() {
		t.Errorf("Ready() = false after OpenLocal, want true")
	}

	sesh, release, err := d.Acquire()
	if err != nil {
		t.Fatalf("Acquire() err = %v", err)
	}
	defer release()
	got, err := digestOf(t, sesh.Inner())
	if err != nil {
		t.Fatalf("GetMetadata() err = %v", err)
	}
	if want := "sha256:a"; got != want {
		t.Errorf("digest = %v, want %v", got, want)
	}
}

func TestSharedDB_OpenLocalWithoutDB(t *testing.T) {
	// Nothing on disk: OpenLocal has to refuse rather than download, leaving that
	// decision to Reload, which is the only path allowed to fetch.
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: filepath.Join(t.TempDir(), "vuls.db")}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.OpenLocal(); err == nil {
		t.Errorf("OpenLocal() err = nil with no db on disk, want an error")
	}
	if d.Ready() {
		t.Errorf("Ready() = true after a failed OpenLocal, want false")
	}
}

func TestSharedDB_Prepare(t *testing.T) {
	// A db on disk is enough to be ready, so Prepare returns without reaching
	// the registry even though this db is stale enough for a refresh to be due.
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a")}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.Prepare(context.Background(), time.Minute); err != nil {
		t.Fatalf("Prepare() err = %v", err)
	}
	defer d.Close()

	if !d.Ready() {
		t.Errorf("Ready() = false after Prepare, want true")
	}
}

func TestSharedDB_PrepareCancelled(t *testing.T) {
	// Nothing on disk and SkipUpdate to keep the retry loop from downloading:
	// Prepare has to give up on ctx rather than block a shutdown forever.
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: filepath.Join(t.TempDir(), "vuls.db"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := d.Prepare(ctx, time.Minute); err == nil {
		t.Errorf("Prepare() err = nil on a cancelled context, want an error")
	}
	if d.Ready() {
		t.Errorf("Ready() = true after a failed Prepare, want false")
	}
}

func TestSharedDB_Reload(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() err = %v", err)
	}
	defer d.Close()

	if !d.Ready() {
		t.Errorf("Ready() = false after Reload, want true")
	}

	sesh, release, err := d.Acquire()
	if err != nil {
		t.Fatalf("Acquire() err = %v", err)
	}
	defer release()

	got, err := digestOf(t, sesh.Inner())
	if err != nil {
		t.Fatalf("GetMetadata() err = %v", err)
	}
	if want := "sha256:a"; got != want {
		t.Errorf("digest = %v, want %v", got, want)
	}

	// The Session is borrowed: Close must leave the shared db alone, or the
	// request that happened to finish first would take the db away from every
	// other request and from the process.
	sesh.Close()
	if _, err := digestOf(t, sesh.Inner()); err != nil {
		t.Errorf("GetMetadata() after borrowed Close err = %v, want the db to stay open", err)
	}

	// Nothing is due (SkipUpdate) and a db is already installed, so Reload has
	// no reason to churn the handle.
	if err := d.Reload(context.Background()); err != nil {
		t.Fatalf("second Reload() err = %v", err)
	}
	sesh2, release2, err := d.Acquire()
	if err != nil {
		t.Fatalf("second Acquire() err = %v", err)
	}
	defer release2()
	if sesh2.Inner() != sesh.Inner() {
		t.Errorf("second Acquire() returned a different db, want the installed one to be reused")
	}
}

func TestSharedDB_InstallKeepsRetiredGenerationOpenUntilReleased(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() err = %v", err)
	}
	defer d.Close()

	old, releaseOld, err := d.Acquire()
	if err != nil {
		t.Fatalf("Acquire() err = %v", err)
	}

	// A refresh lands while a request is still reading: closing the db it is
	// reading would munmap the file under its query, so the old generation has
	// to outlive the install.
	d.Install(openFixtureDB(t, newFixtureDB(t, "sha256:b")))

	got, err := digestOf(t, old.Inner())
	if err != nil {
		t.Fatalf("GetMetadata() on the retired db err = %v, want it to stay readable", err)
	}
	if want := "sha256:a"; got != want {
		t.Errorf("retired db digest = %v, want %v", got, want)
	}

	// A request arriving after the install gets the new db.
	fresh, releaseFresh, err := d.Acquire()
	if err != nil {
		t.Fatalf("Acquire() after install err = %v", err)
	}
	defer releaseFresh()
	got, err = digestOf(t, fresh.Inner())
	if err != nil {
		t.Fatalf("GetMetadata() on the installed db err = %v", err)
	}
	if want := "sha256:b"; got != want {
		t.Errorf("installed db digest = %v, want %v", got, want)
	}

	// The last reader of a retired db closes it, so a swapped-out db is not
	// leaked for the rest of the process's life.
	inner := old.Inner()
	releaseOld()
	if _, err := digestOf(t, inner); err == nil {
		t.Errorf("GetMetadata() on the released db err = nil, want the db to be closed")
	}
}

func TestSharedDB_ConcurrentAcquire(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.Reload(context.Background()); err != nil {
		t.Fatalf("Reload() err = %v", err)
	}
	defer d.Close()

	// Requests read the shared db concurrently while refreshes swap it under
	// them: run under -race, this is what says the sharing is actually safe.
	installed := newFixtureDB(t, "sha256:b")

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				sesh, release, err := d.Acquire()
				if err != nil {
					t.Errorf("Acquire() err = %v", err)
					return
				}
				if _, err := digestOf(t, sesh.Inner()); err != nil {
					t.Errorf("GetMetadata() err = %v, want the acquired db to stay open", err)
				}
				release()
			}
		})
	}
	for range 4 {
		wg.Go(func() { d.Install(openFixtureDB(t, installed)) })
	}
	wg.Wait()
}
