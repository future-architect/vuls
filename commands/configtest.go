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
	"flag"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/google/subcommands"
	"golang.org/x/net/context"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
)

// ConfigtestCmd is Subcommand
type ConfigtestCmd struct {
	configPath     string
	askKeyPassword bool
	sshExternal    bool

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
		        [-config=/path/to/config.toml]
	        	[-ask-key-password]
	        	[-ssh-external]
		        [-debug]

		        [SERVER]...
`
}

// SetFlags set flag
func (p *ConfigtestCmd) SetFlags(f *flag.FlagSet) {
	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	f.BoolVar(&p.debug, "debug", false, "debug mode")

	f.BoolVar(
		&p.askKeyPassword,
		"ask-key-password",
		false,
		"Ask ssh privatekey password before scanning",
	)

	f.BoolVar(
		&p.sshExternal,
		"ssh-external",
		false,
		"Use external ssh command. Default: Use the Go native implementation")
}

// Execute execute
func (p *ConfigtestCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	var keyPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			logrus.Error(err)
			return subcommands.ExitFailure
		}
	}

	c.Conf.Debug = p.debug

	err = c.Load(p.configPath, keyPass)
	if err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	var servernames []string
	if 0 < len(f.Args()) {
		servernames = f.Args()
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			bytes, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				logrus.Errorf("Failed to read stdin: %s", err)
				return subcommands.ExitFailure
			}
			fields := strings.Fields(string(bytes))
			if 0 < len(fields) {
				servernames = fields
			}
		}
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
			logrus.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(servernames) {
		c.Conf.Servers = target
	}

	// logger
	Log := util.NewCustomLogger(c.ServerInfo{})

	Log.Info("Validating Config...")
	if !c.Conf.Validate() {
		return subcommands.ExitUsageError
	}

	Log.Info("Detecting Server/Contianer OS... ")
	scan.InitServers(Log)

	Log.Info("Checking sudo configuration... ")
	if err := scan.CheckIfSudoNoPasswd(Log); err != nil {
		Log.Errorf("Failed to sudo with nopassword via SSH. Define NOPASSWD in /etc/sudoers on target servers. err: %s", err)
		return subcommands.ExitFailure
	}
	scan.PrintSSHableServerNames()
	return subcommands.ExitSuccess
}
