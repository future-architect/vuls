//go:build !scanner

package subcmds

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/subcommands"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/server"
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
		[-confidence-over=80]
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
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, _ *flag.FlagSet, _ ...any) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)

	if p.configPath == "" {
		for _, cnf := range []config.VulnDictInterface{
			&config.Conf.CveDict,
			&config.Conf.OvalDict,
			&config.Conf.Gost,
			&config.Conf.Exploit,
			&config.Conf.Metasploit,
			&config.Conf.KEVuln,
			&config.Conf.Cti,
		} {
			cnf.Init()
		}
	} else {
		if err := config.Load(p.configPath); err != nil {
			logging.Log.Errorf("Error loading %s. err: %+v", p.configPath, err)
			return subcommands.ExitUsageError
		}
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	logging.Log.Info("Validating DBs...")
	if err := detector.ValidateDBs(config.Conf.CveDict, config.Conf.OvalDict, config.Conf.Gost, config.Conf.Exploit, config.Conf.Metasploit, config.Conf.KEVuln, config.Conf.Cti, config.Conf.LogOpts); err != nil {
		logging.Log.Errorf("Failed to validate DBs. err: %+v", err)
		return subcommands.ExitFailure
	}

	http.Handle("/vuls", server.VulsHandler{
		ToLocalFile: p.toLocalFile,
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
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
