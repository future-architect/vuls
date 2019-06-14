/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"github.com/future-architect/vuls/exploit"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	cvelog "github.com/kotakanbe/go-cve-dictionary/log"
)

// TuiCmd is Subcommand of host discovery mode
type TuiCmd struct {
	configPath  string
	cveDict     c.GoCveDictConf
	ovalDict    c.GovalDictConf
	gostConf    c.GostConf
	exploitConf c.ExploitConf
}

// Name return subcommand name
func (*TuiCmd) Name() string { return "tui" }

// Synopsis return synopsis
func (*TuiCmd) Synopsis() string { return "Run Tui view to analyze vulnerabilities" }

// Usage return usage
func (*TuiCmd) Usage() string {
	return `tui:
	tui
		[-refresh-cve]
		[-config=/path/to/config.toml]
		[-cvss-over=7]
		[-diff]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-results-dir=/path/to/results]
		[-log-dir=/path/to/log]
		[-debug]
		[-debug-sql]
		[-pipe]
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

`
}

// SetFlags set flag
func (p *TuiCmd) SetFlags(f *flag.FlagSet) {
	//  f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "debug SQL")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	wd, _ := os.Getwd()
	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&c.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	f.BoolVar(&c.Conf.RefreshCve, "refresh-cve", false,
		"Refresh CVE information in JSON file under results dir")

	f.Float64Var(&c.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.BoolVar(&c.Conf.Diff, "diff", false,
		"Difference between previous result and current result ")

	f.BoolVar(
		&c.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't report the unscored CVEs")

	f.BoolVar(&c.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't report the unfixed CVEs")

	f.BoolVar(&c.Conf.Pipe, "pipe", false, "Use stdin via PIPE")

	f.StringVar(&p.cveDict.Type, "cvedb-type", "",
		"DB type of go-cve-dictionary (sqlite3, mysql, postgres or redis)")
	f.StringVar(&p.cveDict.SQLite3Path, "cvedb-path", "", "/path/to/sqlite3")
	f.StringVar(&p.cveDict.URL, "cvedb-url", "",
		"http://go-cve-dictionary.com:1323 or DB connection string")

	f.StringVar(&p.ovalDict.Type, "ovaldb-type", "",
		"DB type of goval-dictionary (sqlite3, mysql, postgres or redis)")
	f.StringVar(&p.ovalDict.SQLite3Path, "ovaldb-path", "", "/path/to/sqlite3")
	f.StringVar(&p.ovalDict.URL, "ovaldb-url", "",
		"http://goval-dictionary.com:1324 or DB connection string")

	f.StringVar(&p.gostConf.Type, "gostdb-type", "",
		"DB type of gost (sqlite3, mysql, postgres or redis)")
	f.StringVar(&p.gostConf.SQLite3Path, "gostdb-path", "", "/path/to/sqlite3")
	f.StringVar(&p.gostConf.URL, "gostdb-url", "",
		"http://gost.com:1325 or DB connection string")

	f.StringVar(&p.exploitConf.Type, "exploitdb-type", "",
		"DB type of exploit (sqlite3, mysql, postgres, redis or http)")
	f.StringVar(&p.exploitConf.SQLite3Path, "exploitdb-sqlite3-path", "", "/path/to/sqlite3")
	f.StringVar(&p.exploitConf.URL, "exploitdb-url", "",
		"http://exploit.com:1326 or DB connection string")

}

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Lang = "en"

	// Setup Logger
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	cvelog.SetLogger(c.Conf.LogDir, false, c.Conf.Debug, false)

	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, err: %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	c.Conf.CveDict.Overwrite(p.cveDict)
	c.Conf.OvalDict.Overwrite(p.ovalDict)
	c.Conf.Gost.Overwrite(p.gostConf)
	c.Conf.Exploit.Overwrite(p.exploitConf)

	var dir string
	var err error
	if c.Conf.Diff {
		dir, err = report.JSONDir([]string{})
	} else {
		dir, err = report.JSONDir(f.Args())
	}
	if err != nil {
		util.Log.Errorf("Failed to read from JSON. err: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnTui() {
		return subcommands.ExitUsageError
	}

	var res models.ScanResults
	if res, err = report.LoadScanResults(dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	util.Log.Infof("Loaded: %s", dir)

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
			util.Log.Errorf("OVAL HTTP server is not running. err: %+v", err)
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

	if res, err = report.FillCveInfos(*dbclient, res, dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}

	for _, r := range res {
		if len(r.Warnings) != 0 {
			util.Log.Warnf("Warning: Some warnings occurred while scanning on %s: %s",
				r.FormatServerName(), r.Warnings)
		}
	}

	return report.RunTui(res)
}
