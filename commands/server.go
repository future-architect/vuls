package commands

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	// "github.com/future-architect/vuls/Server"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/exploit"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/server"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	cvelog "github.com/kotakanbe/go-cve-dictionary/log"
)

// ServerCmd is subcommand for server
type ServerCmd struct {
	configPath  string
	listen      string
	cveDict     c.GoCveDictConf
	ovalDict    c.GovalDictConf
	gostConf    c.GostConf
	exploitConf c.ExploitConf
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
		[-format-json]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-listen=localhost:5515]
		[-cvedb-type=sqlite3|mysql|postgres|redis|http]
		[-cvedb-sqlite3-path=/path/to/cve.sqlite3]
		[-cvedb-url=http://127.0.0.1:1323 or DB connection string]
		[-ovaldb-type=sqlite3|mysql|redis|http]
		[-ovaldb-sqlite3-path=/path/to/oval.sqlite3]
		[-ovaldb-url=http://127.0.0.1:1324 or DB connection string]
		[-gostdb-type=sqlite3|mysql|redis|http]
		[-gostdb-sqlite3-path=/path/to/gost.sqlite3]
		[-gostdb-url=http://127.0.0.1:1325 or DB connection string]
		[-exploitdb-type=sqlite3|mysql|redis|http]
		[-exploitdb-sqlite3-path=/path/to/exploitdb.sqlite3]
		[-exploitdb-url=http://127.0.0.1:1326 or DB connection string]

		[RFC3339 datetime format under results dir]
`
}

// SetFlags set flag
func (p *ServerCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()
	f.StringVar(&p.configPath, "config", "", "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&c.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	f.Float64Var(&c.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means Servering CVSS Score 6.5 and over (default: 0 (means Server all))")

	f.BoolVar(&c.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't Server the unscored CVEs")

	f.BoolVar(&c.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't Server the unfixed CVEs")

	f.StringVar(&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&c.Conf.FormatJSON, "format-json", false, "JSON format")

	f.BoolVar(&c.Conf.ToLocalFile, "to-localfile", false, "Write report to localfile")
	f.StringVar(&p.listen, "listen", "localhost:5515",
		"host:port (default: localhost:5515)")

	f.StringVar(&p.cveDict.Type, "cvedb-type", "",
		"DB type of go-cve-dictionary (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.cveDict.SQLite3Path, "cvedb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.cveDict.URL, "cvedb-url", "",
		"http://go-cve-dictionary.com:1323 or DB connection string")

	f.StringVar(&p.ovalDict.Type, "ovaldb-type", "",
		"DB type of goval-dictionary (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.ovalDict.SQLite3Path, "ovaldb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.ovalDict.URL, "ovaldb-url", "",
		"http://goval-dictionary.com:1324 or DB connection string")

	f.StringVar(&p.gostConf.Type, "gostdb-type", "",
		"DB type of gost (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.gostConf.SQLite3Path, "gostdb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.gostConf.URL, "gostdb-url", "",
		"http://gost.com:1325 or DB connection string")

	f.StringVar(&p.exploitConf.Type, "exploitdb-type", "",
		"DB type of exploit (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.exploitConf.SQLite3Path, "exploitdb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.exploitConf.URL, "exploitdb-url", "",
		"http://exploit.com:1326 or DB connection string")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	cvelog.SetLogger(c.Conf.LogDir, false, c.Conf.Debug, false)

	if p.configPath != "" {
		if err := c.Load(p.configPath, ""); err != nil {
			util.Log.Errorf("Error loading %s. err: %+v", p.configPath, err)
			return subcommands.ExitUsageError
		}
	}

	c.Conf.CveDict.Overwrite(p.cveDict)
	c.Conf.OvalDict.Overwrite(p.ovalDict)
	c.Conf.Gost.Overwrite(p.gostConf)
	c.Conf.Exploit.Overwrite(p.exploitConf)

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	util.Log.Info("Validating db config...")
	if !c.Conf.ValidateOnReportDB() {
		return subcommands.ExitUsageError
	}

	if c.Conf.CveDict.URL != "" {
		if err := report.CveClient.CheckHealth(); err != nil {
			util.Log.Errorf("CVE HTTP server is not running. err: %+v", err)
			util.Log.Errorf("Run go-cve-dictionary as server mode before reporting or run with `-cvedb-type=sqlite3 -cvedb-sqlite3-path` option instead of -cvedb-url")
			return subcommands.ExitFailure
		}
	}

	if c.Conf.OvalDict.URL != "" {
		err := oval.Base{}.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("OVAL HTTP server is not running. err: %s", err)
			util.Log.Errorf("Run goval-dictionary as server mode before reporting or run with `-ovaldb-type=sqlite3 -ovaldb-sqlite3-path` option instead of -ovaldb-url")
			return subcommands.ExitFailure
		}
	}

	if c.Conf.Gost.URL != "" {
		util.Log.Infof("gost: %s", c.Conf.Gost.URL)
		err := gost.Base{}.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("gost HTTP server is not running. err: %+v", err)
			util.Log.Errorf("Run gost as server mode before reporting or run with `-gostdb-type=sqlite3 -gostdb-sqlite3-path` option instead of -gostdb-url")
			return subcommands.ExitFailure
		}
	}

	if c.Conf.Exploit.URL != "" {
		err := exploit.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("exploit HTTP server is not running. err: %+v", err)
			util.Log.Errorf("Run go-exploitdb as server mode before reporting")
			return subcommands.ExitFailure
		}
	}

	dbclient, locked, err := report.NewDBClient(report.DBClientConf{
		CveDictCnf:  c.Conf.CveDict,
		OvalDictCnf: c.Conf.OvalDict,
		GostCnf:     c.Conf.Gost,
		ExploitCnf:  c.Conf.Exploit,
		DebugSQL:    c.Conf.DebugSQL,
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

	http.Handle("/vuls", server.VulsHandler{DBclient: *dbclient})
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
