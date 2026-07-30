package vuls2

import (
	"context"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// SharedDB owns the vuls2 db's lifecycle for a server process: it downloads the
// db, keeps it current in the background, and hands each request a session that
// can only read what is already on disk.
//
// The failure it exists to fix is that fetching used to be request-scoped. A pod
// that came up with no db started listening immediately, so every request that
// arrived found the db missing and began its own multi-gigabyte fetch — several
// at a time, into the same directory, each slow enough to trip the registry's
// stream limits and start over. Here only Prepare and Run fetch, so a fetch is
// single-flight and never blocks a request, and the sessions Acquire hands out
// have SkipUpdate forced, so a request cannot become another thing that
// downloads a db. Ready says whether there is anything to serve at all, so a
// request arriving before the first fetch finishes is refused rather than made
// to wait for it.
//
// It deliberately does not hold one db open for requests to share. Opening the
// db read-only is an mmap of a file the page cache already holds: on a
// full-size (~11 GB) db it measures ~50µs, nothing beside the seconds a
// detection takes. Sharing one handle would save that and cost far more,
// because a session shared across requests cannot carry vuls2's read cache —
// the cache never evicts, so one that outlives a request grows until the
// process is OOM-killed. Going without it makes enrichment re-read and
// re-unmarshal the same advisory and vulnerability records once per root that
// references them: enriching a 4873-CVE result measured 2.4s with a cache and
// 150s without. A handle per request, with a cache per request, is both faster
// and simpler.
type SharedDB struct {
	conf       config.Vuls2Conf
	noProgress bool

	// mu guards ready. Nothing else here is mutable: Prepare and Run are one
	// goroutine, and requests only read conf.
	mu    sync.Mutex
	ready bool
}

// NewSharedDB returns a SharedDB with no db adopted yet. Nothing is fetched or
// opened here, so this does not block; the caller is expected to run Prepare and
// then Run, and to refuse what it cannot serve while Ready is false.
func NewSharedDB(vuls2Conf config.Vuls2Conf, noProgress bool) (*SharedDB, error) {
	// Resolve the defaults up front: Reload has to stat and read the metadata of
	// the very file a request will open, and an empty Path would otherwise send
	// the two at different files.
	conf, err := withDefaults(vuls2Conf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to apply vuls2 config defaults. err: %w", err)
	}
	return &SharedDB{conf: conf, noProgress: noProgress}, nil
}

// Ready reports whether a db this process has validated is on disk and can be
// served. Prepare loops until it holds, and Reload uses it to tell a refresh
// (keep serving what is there) from a first fetch (there is nothing to fall
// back to).
func (d *SharedDB) Ready() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ready
}

// Acquire returns the db session for one request. The caller owns it and must
// Close it (defer it). The db is opened lazily, on the first path that queries
// it, so a request with nothing to detect never opens it at all.
//
// SkipUpdate is forced on, which is what keeps fetching off the request path: a
// server reachable before its first fetch finishes fails the request instead of
// starting a fetch of its own. The digest is not recorded either — SharedDB
// recorded it for the db this session is about to open, and concurrent requests
// writing that global would race the config copy DetectPkgCves makes.
func (d *SharedDB) Acquire() *Session {
	conf := d.conf
	conf.SkipUpdate = true
	return &Session{vuls2Conf: conf, noProgress: d.noProgress, withCache: true}
}

// OpenLocal adopts the db that is already on disk, without downloading
// anything, and fails if there is no usable one there. It opens the db only to
// check it and to read its digest, and closes it again: requests open their own.
//
// This is how a server starts. A db on disk that is merely due for a refresh is
// still a db worth serving, so checking it first means a process that has one
// answers requests as soon as it starts, instead of going without answering
// anything for the length of a multi-gigabyte fetch. Bringing it up to date is
// then the refresher's job, and happens with requests being served throughout.
func (d *SharedDB) OpenLocal() error {
	// SkipUpdate is what tells newDBConfig to open whatever is there and to
	// refuse rather than download when it is missing or the wrong schema.
	conf := d.conf
	conf.SkipUpdate = true
	return d.adopt(conf)
}

// Reload brings the db up to date, downloading it if one is due, and adopts it
// for subsequent requests. The db already on disk keeps serving for the whole
// fetch, and keeps serving if the fetch fails — a refresh that cannot complete
// must not take a working db away.
//
// Only Prepare and Run call this, so at most one fetch is ever in flight.
func (d *SharedDB) Reload(ctx context.Context) error {
	willDownload, err := shouldDownload(d.conf, time.Now())
	if err != nil {
		return xerrors.Errorf("Failed to check whether to download vuls2 db. err: %w", err)
	}

	// With a db already serving, spend a manifest resolve before spending a
	// download: shouldDownload goes by timestamps alone, so a nightly db that
	// has not been rebuilt looks due on every check for as long as it lives.
	// With no db yet there is nothing to compare and nothing to serve either
	// way, so go straight to fetching one.
	if willDownload && d.Ready() {
		switch newer, err := hasNewerRemote(ctx, d.conf); {
		case err != nil:
			// A repository this process cannot resolve is one it cannot download
			// gigabytes from either, so keep serving and retry on the next check
			// rather than starting a fetch that is unlikely to finish.
			logging.Log.Warnf("Failed to check for a newer vuls2 db, keeping the current one. err: %+v", err)
			willDownload = false
		case !newer:
			logging.Log.Debugf("vuls2 db is up to date. repository: %s", d.conf.Repository)
			willDownload = false
		}
	}

	if !willDownload {
		if d.Ready() {
			// Nothing to fetch and something to serve: there is nothing to do.
			return nil
		}
		return d.OpenLocal()
	}

	return d.adopt(d.conf)
}

// adopt opens the db conf points at — downloading it first if conf allows and
// one is due — records its digest for the reports requests will produce, and
// marks it ready. The handle is closed again immediately: it exists only to
// prove the db is usable and to read its metadata.
func (d *SharedDB) adopt(conf config.Vuls2Conf) error {
	sesh, digest, err := openSession(conf, d.noProgress, false)
	if err != nil {
		return xerrors.Errorf("Failed to open vuls2 db. err: %w", err)
	}
	if err := sesh.Storage().Close(); err != nil {
		logging.Log.Warnf("Failed to close vuls2 db. err: %+v", err)
	}
	sesh.Cache().Close()

	// Safe to write here and nowhere else: Prepare and Run are the only callers
	// and they are one goroutine, and this runs before any request opens the db
	// it describes.
	config.Conf.Vuls2.Digest = digest

	d.mu.Lock()
	defer d.mu.Unlock()
	d.ready = true
	return nil
}

// Prepare gets a db ready to serve from and does not return until there is one
// or ctx is done: it takes whatever is on disk if there is anything usable
// there, and otherwise downloads one, retrying every retryInterval for as long
// as that keeps failing.
//
// Server mode runs this in the background and reports Ready on its health
// endpoint meanwhile, so a first start with nothing on disk is reachable and can
// say why it is not serving, instead of going dark for the length of the fetch.
func (d *SharedDB) Prepare(ctx context.Context, retryInterval time.Duration) error {
	err := d.OpenLocal()
	if err == nil {
		return nil
	}
	logging.Log.Infof("No vuls2 db on disk to serve from, fetching one. err: %s", err)

	for {
		err := d.Reload(ctx)
		if err == nil {
			return nil
		}
		logging.Log.Errorf("Failed to prepare vuls2 db, retrying in %s. err: %+v", retryInterval, err)

		select {
		case <-ctx.Done():
			return xerrors.Errorf("Failed to prepare vuls2 db. err: %w", ctx.Err())
		case <-time.After(retryInterval):
		}
	}
}

// Run keeps the db current until ctx is done, re-checking every interval whether
// a newer one is due. It expects Prepare to have adopted one already, and runs
// in the background so a refresh never blocks a request.
//
// A failure is logged and retried on the next tick rather than propagated: the
// point of the interval is that a fetch that keeps failing is retried at a
// bounded rate, instead of being restarted by every request that arrives.
func (d *SharedDB) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.Reload(ctx); err != nil {
				logging.Log.Warnf("Failed to refresh vuls2 db, serving the current one. err: %+v", err)
			}
		}
	}
}
