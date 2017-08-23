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
	"os"
	"path/filepath"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
)

// TuiCmd is Subcommand of host discovery mode
type TuiCmd struct {
	lang       string
	debugSQL   bool
	debug      bool
	configPath string
	logDir     string

	resultsDir string
	refreshCve bool

	cvedbtype        string
	cvedbpath        string
	cveDictionaryURL string

	ovalDBType string
	ovalDBPath string
	ovalDBURL  string

	pipe bool
}

// Name return subcommand name
func (*TuiCmd) Name() string { return "tui" }

// Synopsis return synopsis
func (*TuiCmd) Synopsis() string { return "Run Tui view to analyze vulnerabilities" }

// Usage return usage
func (*TuiCmd) Usage() string {
	return `tui:
	tui
		[-config=/path/to/config.toml]
		[-cvedb-type=sqlite3|mysql|postgres]
		[-cvedb-path=/path/to/cve.sqlite3]
		[-cvedb-url=http://127.0.0.1:1323 or DB connection string]
		[-ovaldb-type=sqlite3|mysql]
		[-ovaldb-path=/path/to/oval.sqlite3]
		[-ovaldb-url=http://127.0.0.1:1324 or DB connection string]
		[-refresh-cve]
		[-results-dir=/path/to/results]
		[-log-dir=/path/to/log]
		[-debug]
		[-debug-sql]
		[-pipe]

`
}

// SetFlags set flag
func (p *TuiCmd) SetFlags(f *flag.FlagSet) {
	//  f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "debug SQL")
	f.BoolVar(&p.debug, "debug", false, "debug mode")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.logDir, "log-dir", defaultLogDir, "/path/to/log")

	wd, _ := os.Getwd()
	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	f.BoolVar(
		&p.refreshCve,
		"refresh-cve",
		false,
		"Refresh CVE information in JSON file under results dir")

	f.StringVar(
		&p.cvedbtype,
		"cvedb-type",
		"sqlite3",
		"DB type for fetching CVE dictionary (sqlite3, mysql or postgres)")

	defaultCveDBPath := filepath.Join(wd, "cve.sqlite3")
	f.StringVar(
		&p.cvedbpath,
		"cvedb-path",
		defaultCveDBPath,
		"/path/to/sqlite3 (For get cve detail from cve.sqlite3)")

	f.StringVar(
		&p.cveDictionaryURL,
		"cvedb-url",
		"",
		"http://cve-dictionary.example.com:1323 or mysql connection string")

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
		"http://goval-dictionary.example.com:1324 or mysql connection string")

	f.BoolVar(
		&p.pipe,
		"pipe",
		false,
		"Use stdin via PIPE")
}

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Lang = "en"

	// Setup Logger
	c.Conf.Debug = p.debug
	c.Conf.DebugSQL = p.debugSQL
	c.Conf.LogDir = p.logDir
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	log := util.Log

	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	c.Conf.ResultsDir = p.resultsDir
	c.Conf.CveDBType = p.cvedbtype
	c.Conf.CveDBPath = p.cvedbpath
	c.Conf.CveDBURL = p.cveDictionaryURL
	c.Conf.OvalDBType = p.ovalDBType
	c.Conf.OvalDBPath = p.ovalDBPath
	c.Conf.OvalDBURL = p.ovalDBURL

	log.Info("Validating config...")
	if !c.Conf.ValidateOnTui() {
		return subcommands.ExitUsageError
	}

	c.Conf.Pipe = p.pipe

	dir, err := report.JSONDir(f.Args())
	if err != nil {
		util.Log.Errorf("Failed to read from JSON: %s", err)
		return subcommands.ExitFailure
	}
	var res models.ScanResults
	if res, err = report.LoadScanResults(dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	util.Log.Infof("Loaded: %s", dir)

	if res, err = report.FillCveInfos(res, dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	return report.RunTui(res)
}
