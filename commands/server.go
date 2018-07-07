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
	lang       string
	debug      bool
	debugSQL   bool
	configPath string
	resultsDir string
	logDir     string

	cvssScoreOver      float64
	ignoreUnscoredCves bool
	ignoreUnfixed      bool

	httpProxy string
	listen    string

	cveDBType string
	cveDBPath string
	cveDBURL  string

	ovalDBType string
	ovalDBPath string
	ovalDBURL  string

	toLocalFile bool

	formatJSON bool
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
		[-cvedb-type=sqlite3|mysql|postgres]
		[-cvedb-path=/path/to/cve.sqlite3]
		[-cvedb-url=http://127.0.0.1:1323 or DB connection string]
		[-ovaldb-type=sqlite3|mysql]
		[-ovaldb-path=/path/to/oval.sqlite3]
		[-ovaldb-url=http://127.0.0.1:1324 or DB connection string]
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
		[-format-short-text]
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

	f.StringVar(
		&p.cveDBType,
		"cvedb-type",
		"sqlite3",
		"DB type for fetching CVE dictionary (sqlite3, mysql or postgres)")

	defaultCveDBPath := filepath.Join(wd, "cve.sqlite3")
	f.StringVar(
		&p.cveDBPath,
		"cvedb-path",
		defaultCveDBPath,
		"/path/to/sqlite3 (For get cve detail from cve.sqlite3)")

	f.StringVar(
		&p.cveDBURL,
		"cvedb-url",
		"",
		"http://cve-dictionary.com:1323 or mysql connection string")

	f.StringVar(
		&p.ovalDBType,
		"ovaldb-type",
		"sqlite3",
		"DB type for fetching OVAL dictionary (sqlite3 or mysql)")

	defaultOvalDBPath := filepath.Join(wd, "oval.sqlite3")
	f.StringVar(
		&p.ovalDBPath,
		"ovaldb-path",
		defaultOvalDBPath,
		"/path/to/sqlite3 (For get oval detail from oval.sqlite3)")

	f.StringVar(
		&p.ovalDBURL,
		"ovaldb-url",
		"",
		"http://goval-dictionary.com:1324 or mysql connection string")

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
	cvelog.SetLogger(p.logDir, false, c.Conf.Debug)

	c.Conf.Lang = p.lang
	c.Conf.ResultsDir = p.resultsDir
	c.Conf.CveDBType = p.cveDBType
	c.Conf.CveDBPath = p.cveDBPath
	c.Conf.CveDBURL = p.cveDBURL
	c.Conf.OvalDBType = p.ovalDBType
	c.Conf.OvalDBPath = p.ovalDBPath
	c.Conf.OvalDBURL = p.ovalDBURL
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
	if c.Conf.CveDBURL != "" {
		util.Log.Infof("cve-dictionary: %s", c.Conf.CveDBURL)
	} else {
		if c.Conf.CveDBType == "sqlite3" {
			util.Log.Infof("cve-dictionary: %s", c.Conf.CveDBPath)
		}
	}

	if c.Conf.OvalDBURL != "" {
		util.Log.Infof("oval-dictionary: %s", c.Conf.OvalDBURL)
		err = oval.Base{}.CheckHTTPHealth()
		if err != nil {
			util.Log.Errorf("OVAL HTTP server is not running. err: %s", err)
			util.Log.Errorf("Run goval-dictionary as server mode before Servering or run with -ovaldb-path option")
			return subcommands.ExitFailure
		}
	} else {
		if c.Conf.OvalDBType == "sqlite3" {
			util.Log.Infof("oval-dictionary: %s", c.Conf.OvalDBPath)
		}
	}

	var dbclient report.DBClient
	if dbclient, err = report.NewDBClient(
		c.Conf.CveDBType,
		c.Conf.CveDBURL,
		c.Conf.CveDBPath,
		c.Conf.OvalDBType,
		c.Conf.OvalDBURL,
		c.Conf.OvalDBPath,
		c.Conf.DebugSQL,
	); err != nil {
		util.Log.Errorf("Failed to New DB Clients: %s", err)
		return subcommands.ExitFailure
	}
	defer dbclient.CloseDB()

	http.Handle("/", server.VulsHandler{
		DBclient: dbclient,
	})
	util.Log.Infof("Listening on %s", p.listen)
	if err := http.ListenAndServe(p.listen, nil); err != nil {
		util.Log.Errorf("Failed to start server: %s", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
