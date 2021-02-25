package subcmds

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"

	c "github.com/future-architect/vuls/config"
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
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")

	f.IntVar(&p.timeoutSec, "timeout", 5*60, "Timeout(Sec)")

	f.BoolVar(&p.askKeyPassword, "ask-key-password", false,
		"Ask ssh privatekey password before scanning",
	)

	f.StringVar(&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&c.Conf.Vvv, "vvv", false, "ssh -vvv")
}

// Execute execute
func (p *ConfigtestCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logging.Log = logging.NewCustomLogger(c.Conf.Debug, c.Conf.Quiet, c.Conf.LogDir, "", "")
	logging.Log.Infof("vuls-%s-%s", c.Version, c.Revision)

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

	err = c.Load(p.configPath, keyPass)
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

	targets := make(map[string]c.ServerInfo)
	for _, arg := range servernames {
		found := false
		for servername, info := range c.Conf.Servers {
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
		c.Conf.Servers = targets
	}

	logging.Log.Info("Validating config...")
	if !c.Conf.ValidateOnConfigtest() {
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
