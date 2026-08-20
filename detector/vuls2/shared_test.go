package vuls2_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/db/session/types"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/vuls2"
)

// newFixtureDB writes a db carrying digest as its metadata and returns its path,
// so a test can tell which db it was handed.
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

func TestSharedDB_NotReadyBeforeOpen(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}

	// A db on disk is not a db this process has checked: until OpenLocal or
	// Reload validates one, the server has nothing it can promise to serve.
	if d.Ready() {
		t.Errorf("Ready() = true before OpenLocal, want false")
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

	if !d.Ready() {
		t.Errorf("Ready() = false after OpenLocal, want true")
	}

	sesh := d.Acquire()
	defer sesh.Close()
	inner, err := sesh.Open()
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	got, err := digestOf(t, inner)
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

// TestSharedDB_AcquireCannotFetch is the guarantee that keeps multi-gigabyte
// downloads off the request path: whatever the configured db policy, a session
// handed to a request is barred from fetching.
func TestSharedDB_AcquireCannotFetch(t *testing.T) {
	// SkipUpdate false and a db stale enough that shouldDownload would say yes.
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a")}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}

	sesh := d.Acquire()
	defer sesh.Close()
	if !sesh.SkipsUpdate() {
		t.Errorf("Acquire() session SkipUpdate = false, want the request path barred from fetching")
	}

	// It still opens the stale db, so a request is served rather than refused
	// while the refresher catches up. Reaching the registry would fail this
	// test by hanging or erroring instead.
	if _, err := sesh.Open(); err != nil {
		t.Errorf("Open() err = %v, want the stale db to be served", err)
	}
}

// TestSharedDB_AcquireCarriesCache is what this whole shape exists for: an
// unshared handle is only worth having because it can carry a read cache, and
// enrichment measured ~60x slower without one.
func TestSharedDB_AcquireCarriesCache(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}

	sesh := d.Acquire()
	defer sesh.Close()
	inner, err := sesh.Open()
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	if inner.Cache() == nil {
		t.Errorf("Acquire() session Cache() = nil, want a per-request read cache")
	}
}

// TestSharedDB_AcquireIsIndependent checks that one request finishing does not
// take the db away from another: each holds its own handle.
func TestSharedDB_AcquireIsIndependent(t *testing.T) {
	d, err := vuls2.NewSharedDB(config.Vuls2Conf{Path: newFixtureDB(t, "sha256:a"), SkipUpdate: true}, true)
	if err != nil {
		t.Fatalf("NewSharedDB() err = %v", err)
	}
	if err := d.OpenLocal(); err != nil {
		t.Fatalf("OpenLocal() err = %v", err)
	}

	first := d.Acquire()
	firstInner, err := first.Open()
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	second := d.Acquire()
	defer second.Close()
	secondInner, err := second.Open()
	if err != nil {
		t.Fatalf("second Open() err = %v", err)
	}

	first.Close()
	if _, err := digestOf(t, secondInner); err != nil {
		t.Errorf("GetMetadata() after the other request closed err = %v, want this db to stay open", err)
	}
	// The one that did close is closed, so a request does not leak its handle
	// for the rest of the process's life.
	if _, err := digestOf(t, firstInner); err == nil {
		t.Errorf("GetMetadata() on the closed db err = nil, want it to be closed")
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

	if !d.Ready() {
		t.Errorf("Ready() = false after Reload, want true")
	}

	// Nothing is due (SkipUpdate) and a db is already adopted, so a second
	// Reload has nothing to do and must not fail.
	if err := d.Reload(context.Background()); err != nil {
		t.Fatalf("second Reload() err = %v", err)
	}

	sesh := d.Acquire()
	defer sesh.Close()
	inner, err := sesh.Open()
	if err != nil {
		t.Fatalf("Open() err = %v", err)
	}
	got, err := digestOf(t, inner)
	if err != nil {
		t.Fatalf("GetMetadata() err = %v", err)
	}
	if want := "sha256:a"; got != want {
		t.Errorf("digest = %v, want %v", got, want)
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

	// Requests open, read and close their own handles on the same file while
	// health checks read Ready: under -race, this is what says that giving every
	// request its own handle is safe. bolt takes a shared lock in read-only mode,
	// so these opens do not serialise against each other.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				sesh := d.Acquire()
				inner, err := sesh.Open()
				if err != nil {
					t.Errorf("Open() err = %v", err)
					sesh.Close()
					return
				}
				if _, err := digestOf(t, inner); err != nil {
					t.Errorf("GetMetadata() err = %v, want the acquired db to be readable", err)
				}
				sesh.Close()
			}
		})
	}
	for range 4 {
		wg.Go(func() {
			for range 50 {
				if !d.Ready() {
					t.Errorf("Ready() = false while serving, want true")
					return
				}
			}
		})
	}
	wg.Wait()
}
