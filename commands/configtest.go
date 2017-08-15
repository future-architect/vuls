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

	"github.com/google/subcommands"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
)

// ConfigtestCmd is Subcommand
type ConfigtestCmd struct {
	configPath     string
	logDir         string
	askKeyPassword bool
	containersOnly bool
	deep           bool
	sshNative      bool
	httpProxy      string
	timeoutSec     int

	debug bool
}

// Name return subcommand name
func (*ConfigtestCmd) Name() string { return "configtest" }

// Synopsis return synopsis
func (*ConfigtestCmd) Synopsis() string { return "Test configuration" }

// Usage return usage
func (*ConfigtestCmd) Usage() string {
	return `configtest:
	configtest
			[-deep]
			[-config=/path/to/config.toml]
			[-log-dir=/path/to/log]
			[-ask-key-password]
			[-timeout=300]
			[-ssh-external]
			[-containers-only]
			[-http-proxy=http://192.168.0.1:8080]
			[-debug]

			[SERVER]...
`
}

// SetFlags set flag
func (p *ConfigtestCmd) SetFlags(f *flag.FlagSet) {
	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&p.logDir, "log-dir", defaultLogDir, "/path/to/log")

	f.BoolVar(&p.debug, "debug", false, "debug mode")

	f.IntVar(&p.timeoutSec, "timeout", 5*60, "Timeout(Sec)")

	f.BoolVar(
		&p.askKeyPassword,
		"ask-key-password",
		false,
		"Ask ssh privatekey password before scanning",
	)

	f.BoolVar(&p.deep, "deep", false, "Config test for deep scan mode")

	f.StringVar(
		&p.httpProxy,
		"http-proxy",
		"",
		"http://proxy-url:port (default: empty)",
	)

	f.BoolVar(
		&p.sshNative,
		"ssh-native-insecure",
		false,
		"Use Native Go implementation of SSH. Default: Use the external command")

	f.BoolVar(
		&p.containersOnly,
		"containers-only",
		false,
		"Test containers only. Default: Test both of hosts and containers")
}

// Execute execute
func (p *ConfigtestCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// Setup Logger
	c.Conf.Debug = p.debug
	c.Conf.LogDir = p.logDir
	util.Log = util.NewCustomLogger(c.ServerInfo{})

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
		util.Log.Errorf("Error loading %s, %s", p.configPath, err)
		util.Log.Errorf("If you update Vuls and get this error, there may be incompatible changes in config.toml")
		util.Log.Errorf("Please check README: https://github.com/future-architect/vuls#configuration")
		return subcommands.ExitUsageError
	}
	c.Conf.SSHNative = p.sshNative
	c.Conf.HTTPProxy = p.httpProxy
	c.Conf.ContainersOnly = p.containersOnly
	c.Conf.Deep = p.deep

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
		util.Log.Errorf("Failed to init servers: %s", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Checking dependencies...")
	scan.CheckDependencies(p.timeoutSec)

	util.Log.Info("Checking sudo settings...")
	scan.CheckIfSudoNoPasswd(p.timeoutSec)

	scan.PrintSSHableServerNames()
	return subcommands.ExitSuccess
}
