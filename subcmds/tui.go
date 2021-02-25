// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/utils"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
	"github.com/future-architect/vuls/tui"
	"github.com/google/subcommands"
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
		[-diff-minus]
		[-diff-plus]
		[-ignore-unscored-cves]
		[-ignore-unfixed]
		[-results-dir=/path/to/results]
		[-log-dir=/path/to/log]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-no-progress]
		[-pipe]
		[-trivy-cachedb-dir=/path/to/dir]

`
}

// SetFlags set flag
func (p *TuiCmd) SetFlags(f *flag.FlagSet) {
	//  f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "debug SQL")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")
	f.BoolVar(&c.Conf.NoProgress, "no-progress", false, "Suppress progress bar")

	defaultLogDir := logging.GetDefaultLogDir()
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
		"Plus Difference between previous result and current result")

	f.BoolVar(&c.Conf.DiffPlus, "diff-plus", false,
		"Plus Difference between previous result and current result")

	f.BoolVar(&c.Conf.DiffMinus, "diff-minus", false,
		"Minus Difference between previous result and current result")

	f.BoolVar(
		&c.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't report the unscored CVEs")

	f.BoolVar(&c.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't report the unfixed CVEs")

	f.BoolVar(&c.Conf.Pipe, "pipe", false, "Use stdin via PIPE")

	f.StringVar(&c.Conf.TrivyCacheDBDir, "trivy-cachedb-dir",
		utils.DefaultCacheDir(), "/path/to/dir")
}

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(c.Conf.Debug, c.Conf.Quiet, c.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", c.Version, c.Revision)
	if err := c.Load(p.configPath, ""); err != nil {
		logging.Log.Errorf("Error loading %s, err: %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	c.Conf.Lang = "en"

	if c.Conf.Diff {
		c.Conf.DiffPlus = true
		c.Conf.DiffMinus = true
	}
	var dir string
	var err error
	if c.Conf.DiffPlus || c.Conf.DiffMinus {
		dir, err = reporter.JSONDir([]string{})
	} else {
		dir, err = reporter.JSONDir(f.Args())
	}
	if err != nil {
		logging.Log.Errorf("Failed to read from JSON. err: %+v", err)
		return subcommands.ExitFailure
	}

	logging.Log.Info("Validating config...")
	if !c.Conf.ValidateOnTui() {
		return subcommands.ExitUsageError
	}

	var res models.ScanResults
	if res, err = reporter.LoadScanResults(dir); err != nil {
		logging.Log.Error(err)
		return subcommands.ExitFailure
	}
	logging.Log.Infof("Loaded: %s", dir)

	for _, cnf := range []c.VulnDictInterface{
		&c.Conf.CveDict,
		&c.Conf.OvalDict,
		&c.Conf.Gost,
		&c.Conf.Exploit,
		&c.Conf.Metasploit,
	} {
		if err := cnf.Validate(); err != nil {
			logging.Log.Errorf("Failed to validate VulnDict: %+v", err)
			return subcommands.ExitFailure
		}

		if err := cnf.CheckHTTPHealth(); err != nil {
			logging.Log.Errorf("Run as server mode before reporting: %+v", err)
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
		logging.Log.Errorf("SQLite3 is locked. Close other DB connections and try again: %+v", err)
		return subcommands.ExitFailure
	}

	if err != nil {
		logging.Log.Errorf("Failed to init DB Clients. err: %+v", err)
		return subcommands.ExitFailure
	}

	defer dbclient.CloseDB()

	if res, err = detector.Detect(*dbclient, res, dir); err != nil {
		logging.Log.Error(err)
		return subcommands.ExitFailure
	}

	for _, r := range res {
		if len(r.Warnings) != 0 {
			logging.Log.Warnf("Warning: Some warnings occurred while scanning on %s: %s",
				r.FormatServerName(), r.Warnings)
		}
	}

	return tui.RunTui(res)
}
