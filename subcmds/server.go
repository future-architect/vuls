//go:build !scanner

package subcmds

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/google/subcommands"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/server"
)

const (
	// dbRefreshInterval is how often the server re-checks whether a newer vuls2
	// db is due. Whether one actually gets downloaded is decided per check
	// against the db's own metadata, so this only sets how promptly a due
	// refresh is noticed.
	dbRefreshInterval = 1 * time.Hour

	// dbRetryInterval is how long the server waits before retrying a vuls2 db it
	// has not managed to open yet, during startup. It bounds the retry rate of a
	// fetch that keeps failing, which used to be driven by request arrivals
	// instead.
	dbRetryInterval = 1 * time.Minute
)

// ServerCmd is subcommand for server
type ServerCmd struct {
	configPath     string
	listen         string
	toLocalFile    bool
	maxConcurrency int
}

// Name return subcommand name
func (*ServerCmd) Name() string { return "server" }

// Synopsis return synopsis
func (*ServerCmd) Synopsis() string { return "Server" }

// Usage return usage
func (*ServerCmd) Usage() string {
	return `Server:
	Server
		[-lang=en|ja]
		[-config=/path/to/config.toml]
		[-log-to-file]
		[-log-dir=/path/to/log]
		[-cvss-over=7]
		[-confidence-over=80]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-to-localfile]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-listen=localhost:5515]
		[-max-concurrency=4]

		[RFC3339 datetime format under results dir]
`
}

// SetFlags set flag
func (p *ServerCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&config.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&config.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&config.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&config.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := logging.GetDefaultLogDir()
	f.StringVar(&config.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&config.Conf.LogToFile, "log-to-file", false, "Output log to file")

	f.Float64Var(&config.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means Servering CVSS Score 6.5 and over (default: 0 (means Server all))")

	f.IntVar(&config.Conf.ConfidenceScoreOver, "confidence-over", 80,
		"-confidence-over=40 means reporting Confidence Score 40 and over (default: 80)")

	f.BoolVar(&config.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't Server the unscored CVEs")

	f.BoolVar(&config.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't show the unfixed CVEs")

	f.StringVar(&config.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&p.toLocalFile, "to-localfile", false, "Write report to localfile")
	f.StringVar(&p.listen, "listen", "localhost:5515",
		"host:port (default: localhost:5515)")

	f.IntVar(&p.maxConcurrency, "max-concurrency", runtime.GOMAXPROCS(0),
		"Maximum number of scan results detected in parallel, 0 for unlimited (default: GOMAXPROCS)")
}

// Execute execute
func (p *ServerCmd) Execute(ctx context.Context, _ *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)

	if p.configPath != "" {
		if err := config.Load(p.configPath); err != nil {
			logging.Log.Errorf("Error loading %s. err: %+v", p.configPath, err)
			return subcommands.ExitUsageError
		}
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	// Own the vuls2 db here, for the whole process, rather than per request: a
	// request must never be the thing that downloads a multi-gigabyte db, and
	// every request should read the one db this process already has open.
	// Progress bars are off unconditionally — a server's fetch reports itself
	// through the log, and a bar redrawing itself into a container log is
	// unreadable.
	db, err := vuls2.NewSharedDB(config.Conf.Vuls2, true)
	if err != nil {
		logging.Log.Errorf("Failed to configure vuls2 db. err: %+v", err)
		return subcommands.ExitFailure
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Open the db in the background so the listener comes up right away and can
	// say that it is still downloading, rather than the port simply being closed
	// for the length of a multi-gigabyte fetch. Once a db is open, the same
	// goroutine keeps it current, so a request never waits on a fetch and only
	// one fetch ever runs at a time.
	go func() {
		if err := db.Prepare(ctx, dbRetryInterval); err != nil {
			logging.Log.Errorf("Failed to prepare vuls2 db. err: %+v", err)
			return
		}
		logging.Log.Infof("vuls2 db is ready")
		db.Run(ctx, dbRefreshInterval)
	}()

	http.Handle("/vuls", server.NewVulsHandler(p.toLocalFile, db, p.maxConcurrency))
	// /health reports whether this server can answer at all: with no db open,
	// /vuls can only fail, so traffic should be kept away until it is. Point a
	// readiness probe at it — a liveness probe would restart the process partway
	// through the first fetch and start the download over from nothing.
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		if !db.Ready() {
			http.Error(w, "vuls2 db is not ready", http.StatusServiceUnavailable)
			return
		}
		if _, err := fmt.Fprintf(w, "ok"); err != nil {
			logging.Log.Errorf("Failed to print server health. err: %+v", err)
		}
	})
	logging.Log.Infof("Listening on %s", p.listen)
	if err := http.ListenAndServe(p.listen, nil); err != nil {
		logging.Log.Errorf("Failed to start server. err: %+v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
