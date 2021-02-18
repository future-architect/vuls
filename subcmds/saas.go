package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/saas"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
)

// SaaSCmd is subcommand for FutureVuls
type SaaSCmd struct {
	configPath string
}

// Name return subcommand name
func (*SaaSCmd) Name() string { return "saas" }

// Synopsis return synopsis
func (*SaaSCmd) Synopsis() string { return "upload to FutureVuls" }

// Usage return usage
func (*SaaSCmd) Usage() string {
	return `saas:
	saas
		[-config=/path/to/config.toml]
		[-results-dir=/path/to/results]
		[-log-dir=/path/to/log]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-debug-sql]
		[-quiet]
		[-no-progress]
`
}

// SetFlags set flag
func (p *SaaSCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.Conf.Lang, "lang", "en", "[en|ja]")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&c.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")
	f.BoolVar(&c.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")
	f.BoolVar(&c.Conf.NoProgress, "no-progress", false, "Suppress progress bar")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&c.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	f.StringVar(
		&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")
}

// Execute execute
func (p *SaaSCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	util.Log = util.NewCustomLogger(c.ServerInfo{})
	if err := c.Load(p.configPath, ""); err != nil {
		util.Log.Errorf("Error loading %s, %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	dir, err := report.JSONDir(f.Args())
	if err != nil {
		util.Log.Errorf("Failed to read from JSON: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnSaaS() {
		return subcommands.ExitUsageError
	}

	var loaded models.ScanResults
	if loaded, err = report.LoadScanResults(dir); err != nil {
		util.Log.Error(err)
		return subcommands.ExitFailure
	}
	util.Log.Infof("Loaded: %s", dir)

	var res models.ScanResults
	hasError := false
	for _, r := range loaded {
		if len(r.Errors) == 0 {
			res = append(res, r)
		} else {
			util.Log.Errorf("Ignored since errors occurred during scanning: %s, err: %v",
				r.ServerName, r.Errors)
			hasError = true
		}
	}

	if len(res) == 0 {
		return subcommands.ExitFailure
	}

	for _, r := range res {
		util.Log.Debugf("%s: %s",
			r.ServerInfo(),
			pp.Sprintf("%s", c.Conf.Servers[r.ServerName]))
	}

	// Ensure UUIDs of scan target servers in config.toml
	if err := saas.EnsureUUIDs(c.Conf.Servers, p.configPath, res); err != nil {
		util.Log.Errorf("Failed to ensure UUIDs. err: %+v", err)
		return subcommands.ExitFailure
	}

	var w report.ResultWriter = saas.Writer{}
	if err := w.Write(res...); err != nil {
		util.Log.Errorf("Failed to upload. err: %+v", err)
		return subcommands.ExitFailure
	}

	if hasError {
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
