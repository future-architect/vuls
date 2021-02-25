// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	// "github.com/future-architect/vuls/Server"

	"github.com/future-architect/vuls/config"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/server"
	"github.com/future-architect/vuls/util"
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
	f.StringVar(&c.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&c.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	f.Float64Var(&c.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means Servering CVSS Score 6.5 and over (default: 0 (means Server all))")

	f.BoolVar(&c.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't Server the unscored CVEs")

	f.BoolVar(&c.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't show the unfixed CVEs")

	f.StringVar(&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&p.toLocalFile, "to-localfile", false, "Write report to localfile")
	f.StringVar(&p.listen, "listen", "localhost:5515",
		"host:port (default: localhost:5515)")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.Log = util.NewCustomLogger(c.Conf.Debug, c.Conf.Quiet, c.Conf.LogDir, "", "")
	util.Log.Infof("vuls-%s-%s", config.Version, config.Revision)
	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s. err: %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	for _, cnf := range []config.VulnDictInterface{
		&c.Conf.CveDict,
		&c.Conf.OvalDict,
		&c.Conf.Gost,
		&c.Conf.Exploit,
		&c.Conf.Metasploit,
	} {
		if err := cnf.Validate(); err != nil {
			util.Log.Errorf("Failed to validate VulnDict: %+v", err)
			return subcommands.ExitFailure
		}

		if err := cnf.CheckHTTPHealth(); err != nil {
			util.Log.Errorf("Run as server mode before reporting: %+v", err)
			return subcommands.ExitFailure
		}
	}

	dbclient, locked, err := detector.NewDBClient(detector.DBClientConf{
		CveDictCnf:    c.Conf.CveDict,
		OvalDictCnf:   c.Conf.OvalDict,
		GostCnf:       c.Conf.Gost,
		ExploitCnf:    c.Conf.Exploit,
		MetasploitCnf: c.Conf.Metasploit,
		DebugSQL:      c.Conf.DebugSQL,
	})
	if locked {
		util.Log.Errorf("SQLite3 is locked. Close other DB connections and try again: %+v", err)
		return subcommands.ExitFailure
	}

	if err != nil {
		util.Log.Errorf("Failed to init DB Clients. err: %+v", err)
		return subcommands.ExitFailure
	}

	defer dbclient.CloseDB()

	http.Handle("/vuls", server.VulsHandler{
		DBclient:    *dbclient,
		ToLocalFile: p.toLocalFile,
	})
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ok")
	})
	util.Log.Infof("Listening on %s", p.listen)
	if err := http.ListenAndServe(p.listen, nil); err != nil {
		util.Log.Errorf("Failed to start server. err: %+v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
