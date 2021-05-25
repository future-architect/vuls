package subcmds

import (
	"context"
	"flag"
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
	"github.com/future-architect/vuls/saas"
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
		[-log-to-file]
		[-log-dir=/path/to/log]
		[-http-proxy=http://192.168.0.1:8080]
		[-debug]
		[-quiet]
`
}

// SetFlags set flag
func (p *SaaSCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&config.Conf.Debug, "debug", false, "debug mode")
	f.BoolVar(&config.Conf.Quiet, "quiet", false, "Quiet mode. No output on stdout")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&config.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := logging.GetDefaultLogDir()
	f.StringVar(&config.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&config.Conf.LogToFile, "log-to-file", false, "Output log to file")

	f.StringVar(
		&config.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")
}

// Execute execute
func (p *SaaSCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)
	if err := config.Load(p.configPath, ""); err != nil {
		logging.Log.Errorf("Error loading %s, %+v", p.configPath, err)
		return subcommands.ExitUsageError
	}

	dir, err := reporter.JSONDir(config.Conf.ResultsDir, f.Args())
	if err != nil {
		logging.Log.Errorf("Failed to read from JSON: %+v", err)
		return subcommands.ExitFailure
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnSaaS() {
		return subcommands.ExitUsageError
	}

	var loaded models.ScanResults
	if loaded, err = reporter.LoadScanResults(dir); err != nil {
		logging.Log.Error(err)
		return subcommands.ExitFailure
	}
	logging.Log.Infof("Loaded: %s", dir)

	var res models.ScanResults
	hasError := false
	for _, r := range loaded {
		if len(r.Errors) == 0 {
			res = append(res, r)
		} else {
			logging.Log.Errorf("Ignored since errors occurred during scanning: %s, err: %v",
				r.ServerName, r.Errors)
			hasError = true
		}
	}

	if len(res) == 0 {
		return subcommands.ExitFailure
	}

	for _, r := range res {
		logging.Log.Debugf("%s: %s",
			r.ServerInfo(), pp.Sprintf("%s", config.Conf.Servers[r.ServerName]))
	}

	// Ensure UUIDs of scan target servers in config.toml
	if err := saas.EnsureUUIDs(config.Conf.Servers, p.configPath, res); err != nil {
		logging.Log.Errorf("Failed to ensure UUIDs. err: %+v", err)
		return subcommands.ExitFailure
	}

	var w reporter.ResultWriter = saas.Writer{}
	if err := w.Write(res...); err != nil {
		logging.Log.Errorf("Failed to upload. err: %+v", err)
		return subcommands.ExitFailure
	}

	if hasError {
		return subcommands.ExitFailure
	}

	if !config.Conf.Debug {
		if err := os.RemoveAll(dir); err != nil {
			logging.Log.Warnf("Failed to remove %s. err: %+v", dir, err)
		}
		symlink := filepath.Join(config.Conf.ResultsDir, "current")
		err := os.Remove(symlink)
		if err != nil {
			logging.Log.Warnf("Failed to remove %s. err: %+v", dir, err)
		}
	}

	return subcommands.ExitSuccess
}
