/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/server"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	cvelog "github.com/kotakanbe/go-cve-dictionary/log"
)

// ServerCmd is subcommand for server
type ServerCmd struct {
	lang               string
	debug              bool
	debugSQL           bool
	configPath         string
	resultsDir         string
	logDir             string
	cvssScoreOver      float64
	ignoreUnscoredCves bool
	ignoreUnfixed      bool
	httpProxy          string
	listen             string
	toLocalFile        bool
	formatJSON         bool
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
		[-diff]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-to-email]
		[-to-slack]
		[-to-stride]
		[-to-hipchat]
		[-to-chatwork]
		[-to-localfile]
		[-to-s3]
		[-to-azure-blob]
		[-format-json]
		[-format-xml]
		[-format-one-email]
		[-format-one-line-text]
		[-format-list]
		[-format-full-text]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-listen=localhost:5515]

		[RFC3339 datetime format under results dir]
`
}

// SetFlags set flag
func (p *ServerCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debug, "debug", false, "debug mode")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.logDir, "log-dir", defaultLogDir, "/path/to/log")

	f.Float64Var(
		&p.cvssScoreOver,
		"cvss-over",
		0,
		"-cvss-over=6.5 means Servering CVSS Score 6.5 and over (default: 0 (means Server all))")

	f.BoolVar(
		&p.ignoreUnscoredCves,
		"ignore-unscored-cves",
		false,
		"Don't Server the unscored CVEs")

	f.BoolVar(
		&p.ignoreUnfixed,
		"ignore-unfixed",
		false,
		"Don't Server the unfixed CVEs")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)")
	f.BoolVar(&p.formatJSON,
		"format-json",
		false,
		fmt.Sprintf("JSON format"))

	f.BoolVar(&p.toLocalFile,
		"to-localfile",
		false,
		fmt.Sprintf("Write report to localfile"))
	f.StringVar(
		&p.listen,
		"listen",
		"localhost:5515",
		"host:port (default: localhost:5515)")
}

// Execute execute
func (p *ServerCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL
	c.Conf.LogDir = p.logDir
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	cvelog.SetLogger(p.logDir, false, c.Conf.Debug, false)

	c.Conf.Lang = p.lang
	c.Conf.ResultsDir = p.resultsDir
	c.Conf.CvssScoreOver = p.cvssScoreOver
	c.Conf.IgnoreUnscoredCves = p.ignoreUnscoredCves
	c.Conf.IgnoreUnfixed = p.ignoreUnfixed
	c.Conf.HTTPProxy = p.httpProxy

	c.Conf.ToLocalFile = p.toLocalFile

	c.Conf.FormatJSON = p.formatJSON

	var err error

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}
	if err = report.CveClient.CheckHealth(); err != nil {
		util.Log.Errorf("CVE HTTP server is not running. err: %s", err)
		util.Log.Errorf("Run go-cve-dictionary as server mode before Servering or run with -cvedb-path option")
		return subcommands.ExitFailure
	}
	if c.Conf.Report.CveDict.URL != "" {
		util.Log.Infof("cve-dictionary: %s", c.Conf.Report.CveDict.URL)
	} else {
		if c.Conf.Report.CveDict.Type == "sqlite3" {
			util.Log.Infof("cve-dictionary: %s", c.Conf.Report.CveDict.Path)
		}
	}

	if c.Conf.Report.OvalDict.URL != "" {
		util.Log.Infof("oval-dictionary: %s", c.Conf.Report.OvalDict.URL)
		err = oval.Base{}.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("OVAL HTTP server is not running. err: %s", err)
			util.Log.Errorf("Run goval-dictionary as server mode before Servering or run with -ovaldb-path option")
			return subcommands.ExitFailure
		}
	} else {
		if c.Conf.Report.OvalDict.Type == "sqlite3" {
			util.Log.Infof("oval-dictionary: %s", c.Conf.Report.OvalDict.Path)
		}
	}

	dbclient, locked, err := report.NewDBClient(report.DBClientConf{
		CveDictCnf:  c.Conf.Report.CveDict,
		OvalDictCnf: c.Conf.Report.OvalDict,
		GostCnf:     c.Conf.Report.Gost,
		DebugSQL:    c.Conf.DebugSQL,
	})
	if locked {
		util.Log.Errorf("SQLite3 is locked. Close other DB connections and try again: %s", err)
		return subcommands.ExitFailure
	}

	if err != nil {
		util.Log.Errorf("Failed to init DB Clients: %s", err)
		return subcommands.ExitFailure
	}

	defer dbclient.CloseDB()

	http.Handle("/", server.VulsHandler{DBclient: *dbclient})
	util.Log.Infof("Listening on %s", p.listen)
	if err := http.ListenAndServe(p.listen, nil); err != nil {
		util.Log.Errorf("Failed to start server: %s", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
