package vuls2

import (
	"context"
	"sync"
	"time"

	"golang.org/x/xerrors"

	"github.com/MaineK00n/vuls2/pkg/db/session"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// SharedDB owns the vuls2 db for the lifetime of a server process: it opens the
// db once and lets every request query that one open handle, instead of each
// request opening (and possibly downloading) its own.
//
// That per-request ownership was the cause of two distinct failures. A pod that
// came up with no db on disk started listening immediately, so every request
// that arrived found the db missing and started its own multi-gigabyte fetch —
// several at a time, into the same directory, each slow enough to trip the
// registry's stream limits and start over. And a request that did find a db
// opened bolt three times, built a read cache, then threw the cache away, so
// concurrent requests shared nothing and re-read the same CVEs from disk.
// Hoisting the db out of the request path fixes both: only Prepare and the
// refresher fetch, so a fetch is single-flight and never blocks a request, and
// Ready reports whether there is a db to serve from at all, so a request that
// arrives before the first fetch finishes is refused rather than made to fetch.
//
// bolt allows concurrent read transactions on one open handle and every vuls2
// storage read is such a transaction, so sharing the handle is safe. The
// session deliberately carries no read cache — see newDBConfig for why one that
// outlives a request cannot be shared safely.
type SharedDB struct {
	conf       config.Vuls2Conf
	noProgress bool

	// mu guards cur and every generation's refs/retired. Critical sections are
	// short by construction: fetching and opening a db happen outside it, so a
	// request never waits on a download, and a long-running request never keeps
	// the refresher from installing a new db.
	mu  sync.Mutex
	cur *generation
}

// generation is one open db. A new db is installed alongside the generation it
// replaces rather than swapped into it, because requests that are still reading
// the old one have to keep working: closing a db munmaps it, which would fault
// a query mid-flight. Whoever drops the last reference to a retired generation
// closes it.
type generation struct {
	sesh    *session.Session
	refs    int
	retired bool
}

// NewSharedDB returns a SharedDB with no db open yet. Nothing is fetched or
// opened here, so this does not block; the caller is expected to run Prepare and
// then Run, and to refuse what it cannot serve while Ready is false.
func NewSharedDB(vuls2Conf config.Vuls2Conf, noProgress bool) (*SharedDB, error) {
	// Resolve the defaults up front: Reload has to stat and read the metadata of
	// the very file openSession will open, and an empty Path would otherwise
	// send the two at different files.
	conf, err := withDefaults(vuls2Conf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to apply vuls2 config defaults. err: %w", err)
	}
	return &SharedDB{conf: conf, noProgress: noProgress}, nil
}

// Ready reports whether a db is open and can be queried. Prepare loops until it
// holds, and Reload uses it to tell a refresh (keep serving the db that is
// already open) from a first open (there is nothing to fall back to).
func (d *SharedDB) Ready() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cur != nil
}

// Acquire pins the open db and returns a Session to query it plus the func that
// unpins it, which the caller must call exactly once (defer it). The Session is
// borrowed: closing it is a no-op, and the db stays open for the next request.
//
// It fails rather than opening one if no db is open, which is what keeps
// fetching off the request path: a server that is reachable before its first
// fetch finishes refuses the request instead of starting a fetch of its own.
func (d *SharedDB) Acquire() (*Session, func(), error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cur == nil {
		return nil, nil, xerrors.Errorf("vuls2 db is not ready yet. path: %s", d.conf.Path)
	}

	g := d.cur
	g.refs++
	return &Session{sesh: g.sesh, borrowed: true}, func() { d.release(g) }, nil
}

// release drops one reference to g, closing it if it was retired while this was
// the last request reading it.
func (d *SharedDB) release(g *generation) {
	d.mu.Lock()
	defer d.mu.Unlock()

	g.refs--
	d.closeIfIdle(g)
}

// closeIfIdle closes a retired generation once nothing is reading it. Must be
// called with d.mu held.
func (d *SharedDB) closeIfIdle(g *generation) {
	if g.sesh == nil || !g.retired || g.refs > 0 {
		return
	}
	if err := g.sesh.Storage().Close(); err != nil {
		logging.Log.Warnf("Failed to close vuls2 db. err: %+v", err)
	}
	g.sesh.Cache().Close()
	g.sesh = nil
}

// OpenLocal installs the db that is already on disk, without downloading
// anything, and fails if there is no usable one there.
//
// This is how a server starts: a db on disk that is merely due for a refresh is
// still a db worth serving, so opening it first means a process that has one
// answers requests in the time it takes to mmap a file, instead of going
// without answering anything for the length of a multi-gigabyte fetch. Bringing
// it up to date is then the refresher's job, and happens with requests being
// served the whole time.
func (d *SharedDB) OpenLocal() error {
	// SkipUpdate is what tells newDBConfig to open whatever is there and to
	// refuse rather than download when it is missing or the wrong schema.
	conf := d.conf
	conf.SkipUpdate = true

	sesh, err := openSession(conf, d.noProgress, false)
	if err != nil {
		return xerrors.Errorf("Failed to open vuls2 db. err: %w", err)
	}

	d.install(sesh)
	return nil
}

// Reload opens the db, downloading it first if one is due, and installs it for
// subsequent requests to use. The db already installed keeps serving for the
// whole fetch and open, and keeps serving if either fails — a refresh that
// cannot complete must not take a working db away.
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
			// Nothing to fetch and something to serve: re-opening the same file
			// would only churn the handle.
			return nil
		}
		return d.OpenLocal()
	}

	sesh, err := openSession(d.conf, d.noProgress, false)
	if err != nil {
		return xerrors.Errorf("Failed to open vuls2 db. err: %w", err)
	}

	d.install(sesh)
	return nil
}

// install makes sesh the db new requests get, and retires the one it replaces.
func (d *SharedDB) install(sesh *session.Session) {
	d.mu.Lock()
	defer d.mu.Unlock()

	old := d.cur
	d.cur = &generation{sesh: sesh}
	if old != nil {
		old.retired = true
		// Closes here if no request is reading it; otherwise the last release
		// does. Requests that already hold it keep reading the file they
		// opened: fetch renames the new db over the old path, so the old inode
		// stays valid until its last reader lets go.
		d.closeIfIdle(old)
	}
}

// Prepare gets a db open to serve from and does not return until it has one or
// ctx is done: it takes whatever is on disk if there is anything usable there,
// and otherwise downloads one, retrying every retryInterval for as long as that
// keeps failing.
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
		if err := d.Reload(ctx); err == nil {
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
// a newer one is due. It expects Prepare to have installed one already, and
// runs in the background so a refresh never blocks a request.
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

// Close closes the db. Call it once the listener has stopped; a request still
// reading the db closes it when it releases instead, so shutting down does not
// munmap a db out from under a query.
func (d *SharedDB) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cur == nil {
		return
	}
	d.cur.retired = true
	d.closeIfIdle(d.cur)
	d.cur = nil
}
