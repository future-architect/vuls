package commands

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
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
			[-ssh-external]
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

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")

	f.IntVar(&p.timeoutSec, "timeout", 5*60, "Timeout(Sec)")

	f.BoolVar(&p.askKeyPassword, "ask-key-password", false,
		"Ask ssh privatekey password before scanning",
	)

	f.StringVar(&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&c.Conf.SSHNative, "ssh-native-insecure", false,
		"Use Native Go implementation of SSH. Default: Use the external command")

	f.BoolVar(&c.Conf.SSHConfig, "ssh-config", false,
		"Use SSH options specified in ssh_config preferentially")

	f.BoolVar(&c.Conf.ContainersOnly, "containers-only", false,
		"Test containers only. Default: Test both of hosts and containers")

	f.BoolVar(&c.Conf.Vvv, "vvv", false, "ssh -vvv")
}

// Execute execute
func (p *ConfigtestCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// Setup Logger
	util.Log = util.NewCustomLogger(c.ServerInfo{})

	if err := mkdirDotVuls(); err != nil {
		util.Log.Errorf("Failed to create .vuls. err: %+v", err)
		return subcommands.ExitUsageError
	}

	var keyPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			util.Log.Error(err)
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
		util.Log.Errorf("%s\n%+v", strings.Join(msg, "\n"), err)
		return subcommands.ExitUsageError
	}

	var servernames []string
	if 0 < len(f.Args()) {
		servernames = f.Args()
	}

	target := make(map[string]c.ServerInfo)
	for _, arg := range servernames {
		found := false
		for servername, info := range c.Conf.Servers {
			if servername == arg {
				target[servername] = info
				found = true
				break
			}
		}
		if !found {
			util.Log.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(servernames) {
		c.Conf.Servers = target
	}

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnConfigtest() {
		return subcommands.ExitUsageError
	}

	util.Log.Info("Detecting Server/Container OS... ")
	if err := scan.InitServers(p.timeoutSec); err != nil {
		util.Log.Errorf("Failed to init servers. err: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Checking Scan Modes...")
	if err := scan.CheckScanModes(); err != nil {
		util.Log.Errorf("Fix config.toml. err: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Checking dependencies...")
	scan.CheckDependencies(p.timeoutSec)

	util.Log.Info("Checking sudo settings...")
	scan.CheckIfSudoNoPasswd(p.timeoutSec)

	util.Log.Info("It can be scanned with fast scan mode even if warn or err messages are displayed due to lack of dependent packages or sudo settings in fast-root or deep scan mode")

	if scan.PrintSSHableServerNames() {
		return subcommands.ExitSuccess
	}
	return subcommands.ExitFailure
}
