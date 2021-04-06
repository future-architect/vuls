// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/server"
	"github.com/google/subcommands"
)

// ServerCmd is subcommand for server
type ServerCmd struct {
	configPath  string
	listen      string
	toLocalFile bool
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
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-to-localfile]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-listen=localhost:5515]

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

	f.BoolVar(&config.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't Server the unscored CVEs")

	f.BoolVar(&config.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't show the unfixed CVEs")

	f.StringVar(&config.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&p.toLocalFile, "to-localfile", false, "Write report to localfile")
	f.StringVar(&p.listen, "listen", "localhost:5515",
		"host:port (default: localhost:5515)")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)
	if err := config.Load(p.configPath, ""); err != nil {
		logging.Log.Errorf("Error loading %s. err: %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	http.Handle("/vuls", server.VulsHandler{
		ToLocalFile: p.toLocalFile,
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
	logging.Log.Infof("Listening on %s", p.listen)
	if err := http.ListenAndServe(p.listen, nil); err != nil {
		logging.Log.Errorf("Failed to start server. err: %+v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
