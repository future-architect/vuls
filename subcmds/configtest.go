package subcmds

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/scanner"
)

// ConfigtestCmd is Subcommand
type ConfigtestCmd struct {
	configPath     string
	askKeyPassword bool
	timeoutSec     int
}

// Name return subcommand name
func (*ConfigtestCmd) Name() string { return "configtest" }

// Synopsis return synopsis
func (*ConfigtestCmd) Synopsis() string { return "Test configuration" }

// Usage return usage
func (*ConfigtestCmd) Usage() string {
	return `configtest:
	configtest
			[-config=/path/to/config.toml]
			[-log-to-file]
			[-log-dir=/path/to/log]
			[-ask-key-password]
			[-timeout=300]
			[-containers-only]
			[-http-proxy=http://192.168.0.1:8080]
			[-debug]
			[-vvv]

			[SERVER]...
`
}

// SetFlags set flag
func (p *ConfigtestCmd) SetFlags(f *flag.FlagSet) {
	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultLogDir := logging.GetDefaultLogDir()
	f.StringVar(&config.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&config.Conf.LogToFile, "log-to-file", false, "output log to file")
	f.BoolVar(&config.Conf.Debug, "debug", false, "debug mode")

	f.IntVar(&p.timeoutSec, "timeout", 5*60, "Timeout(Sec)")

	f.BoolVar(&p.askKeyPassword, "ask-key-password", false,
		"Ask ssh privatekey password before scanning",
	)

	f.StringVar(&config.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&config.Conf.Vvv, "vvv", false, "ssh -vvv")
}

// Execute execute
func (p *ConfigtestCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(config.Conf.Debug, config.Conf.Quiet, config.Conf.LogToFile, config.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", config.Version, config.Revision)

	if err := mkdirDotVuls(); err != nil {
		logging.Log.Errorf("Failed to create $HOME/.vuls: %+v", err)
		return subcommands.ExitUsageError
	}

	var keyPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			logging.Log.Error(err)
			return subcommands.ExitFailure
		}
	}

	err = config.Load(p.configPath, keyPass)
	if err != nil {
		msg := []string{
			fmt.Sprintf("Error loading %s", p.configPath),
			"If you update Vuls and get this error, there may be incompatible changes in config.toml",
			"Please check config.toml template : https://vuls.io/docs/en/usage-settings.html",
		}
		logging.Log.Errorf("%s\n%+v", strings.Join(msg, "\n"), err)
		return subcommands.ExitUsageError
	}

	var servernames []string
	if 0 < len(f.Args()) {
		servernames = f.Args()
	}

	targets := make(map[string]config.ServerInfo)
	for _, arg := range servernames {
		found := false
		for servername, info := range config.Conf.Servers {
			if servername == arg {
				targets[servername] = info
				found = true
				break
			}
		}
		if !found {
			logging.Log.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(servernames) {
		// if scan target servers are specified by args, set to the config
		config.Conf.Servers = targets
	} else {
		// if not specified by args, scan all servers in the config
		targets = config.Conf.Servers
	}

	logging.Log.Info("Validating config...")
	if !config.Conf.ValidateOnConfigtest() {
		return subcommands.ExitUsageError
	}

	s := scanner.Scanner{
		TimeoutSec: p.timeoutSec,
		Targets:    targets,
	}

	if err := s.Configtest(); err != nil {
		logging.Log.Errorf("Failed to configtest: %+v", err)
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
