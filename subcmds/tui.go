// +build !scanner

package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy/pkg/utils"
	"github.com/future-architect/vuls/config"
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
		[-log-to-file]
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
	f.BoolVar(&config.Conf.DebugSQL, "debug-sql", false, "debug SQL")
	f.BoolVar(&config.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&config.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")
	f.BoolVar(&config.Conf.NoProgress, "no-progress", false, "Suppress progress bar")

	defaultLogDir := logging.GetDefaultLogDir()
	f.StringVar(&config.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&config.Conf.LogToFile, "log-to-file", false, "Output log to file")

	wd, _ := os.Getwd()
	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&config.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	f.BoolVar(&config.Conf.RefreshCve, "refresh-cve", false,
		"Refresh CVE information in JSON file under results dir")

	f.Float64Var(&config.Conf.CvssScoreOver, "cvss-over", 0,
		"-cvss-over=6.5 means reporting CVSS Score 6.5 and over (default: 0 (means report all))")

	f.BoolVar(&config.Conf.Diff, "diff", false,
		"Plus Difference between previous result and current result")

	f.BoolVar(&config.Conf.DiffPlus, "diff-plus", false,
		"Plus Difference between previous result and current result")

	f.BoolVar(&config.Conf.DiffMinus, "diff-minus", false,
		"Minus Difference between previous result and current result")

	f.BoolVar(
		&config.Conf.IgnoreUnscoredCves, "ignore-unscored-cves", false,
		"Don't report the unscored CVEs")

	f.BoolVar(&config.Conf.IgnoreUnfixed, "ignore-unfixed", false,
		"Don't report the unfixed CVEs")

	f.BoolVar(&config.Conf.Pipe, "pipe", false, "Use stdin via PIPE")

	f.StringVar(&config.Conf.TrivyCacheDBDir, "trivy-cachedb-dir",
		utils.DefaultCacheDir(), "/path/to/dir")
}

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)
	if err := config.Load(p.configPath, ""); err != nil {
		logging.Log.Errorf("Error loading %s, err: %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	config.Conf.Lang = "en"

	if config.Conf.Diff {
		config.Conf.DiffPlus = true
		config.Conf.DiffMinus = true
	}
	var dir string
	var err error
	if config.Conf.DiffPlus || config.Conf.DiffMinus {
		dir, err = reporter.JSONDir(config.Conf.ResultsDir, []string{})
	} else {
		dir, err = reporter.JSONDir(config.Conf.ResultsDir, f.Args())
	}
	if err != nil {
		logging.Log.Errorf("Failed to read from JSON. err: %+v", err)
		return subcommands.ExitFailure
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnReport() {
		return subcommands.ExitUsageError
	}

	var res models.ScanResults
	if res, err = reporter.LoadScanResults(dir); err != nil {
		logging.Log.Error(err)
		return subcommands.ExitFailure
	}
	logging.Log.Infof("Loaded: %s", dir)

	if res, err = detector.Detect(res, dir); err != nil {
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
