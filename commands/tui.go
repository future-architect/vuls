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
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	cvelog "github.com/kotakanbe/go-cve-dictionary/log"
)

// TuiCmd is Subcommand of host discovery mode
type TuiCmd struct {
	configPath string
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

`
	//TODO
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
}

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Lang = "en"

	// Setup Logger
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	cvelog.SetLogger(c.Conf.LogDir, false, c.Conf.Debug, false)

	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnTui() {
		return subcommands.ExitUsageError
	}

	var dir string
	var err error
	if c.Conf.Diff {
		dir, err = report.JSONDir([]string{})
	} else {
		dir, err = report.JSONDir(f.Args())
	}
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

	dbclient, locked, err := report.NewDBClient(report.DBClientConf{
		CveDictCnf:  c.Conf.CveDict,
		OvalDictCnf: c.Conf.OvalDict,
		GostCnf:     c.Conf.Gost,
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

	if res, err = report.FillCveInfos(*dbclient, res, dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	return report.RunTui(res)
}
