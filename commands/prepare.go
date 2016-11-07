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

	"github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
)

// PrepareCmd is Subcommand of host discovery mode
type PrepareCmd struct {
	debug      bool
	configPath string

	askSudoPassword bool
	askKeyPassword  bool

	sshExternal bool
}

// Name return subcommand name
func (*PrepareCmd) Name() string { return "prepare" }

// Synopsis return synopsis
func (*PrepareCmd) Synopsis() string {
	return `Install required packages to scan.
				CentOS: yum-plugin-security, yum-plugin-changelog
				Amazon: None
				RHEL:   TODO
				Ubuntu: None

	`
}

// Usage return usage
func (*PrepareCmd) Usage() string {
	return `prepare:
	prepare
			[-config=/path/to/config.toml]
			[-ask-key-password]
			[-debug]
			[-ssh-external]

			[SERVER]...
`
}

// SetFlags set flag
func (p *PrepareCmd) SetFlags(f *flag.FlagSet) {

	f.BoolVar(&p.debug, "debug", false, "debug mode")

	wd, _ := os.Getwd()

	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	f.BoolVar(
		&p.askKeyPassword,
		"ask-key-password",
		false,
		"Ask ssh privatekey password before scanning",
	)

	f.BoolVar(
		&p.askSudoPassword,
		"ask-sudo-password",
		false,
		"[Deprecated] THIS OPTION WAS REMOVED FOR SECURITY REASONS. Define NOPASSWD in /etc/sudoers on target servers and use SSH key-based authentication",
	)

	f.BoolVar(
		&p.sshExternal,
		"ssh-external",
		false,
		"Use external ssh command. Default: Use the Go native implementation")

}

// Execute execute
func (p *PrepareCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	var keyPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			logrus.Error(err)
			return subcommands.ExitFailure
		}
	}
	if p.askSudoPassword {
		logrus.Errorf("[Deprecated] -ask-sudo-password WAS REMOVED FOR SECURITY REASONS. Define NOPASSWD in /etc/sudoers on target servers and use SSH key-based authentication")
		return subcommands.ExitFailure
	}

	err = c.Load(p.configPath, keyPass)
	if err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

	logrus.Infof("Start Preparing (config: %s)", p.configPath)
	target := make(map[string]c.ServerInfo)
	for _, arg := range f.Args() {
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
	if 0 < len(f.Args()) {
		c.Conf.Servers = target
	}

	c.Conf.Debug = p.debug
	c.Conf.SSHExternal = p.sshExternal

	// Set up custom logger
	logger := util.NewCustomLogger(c.ServerInfo{})

	logger.Info("Detecting OS... ")
	if err := scan.InitServers(logger); err != nil {
		logger.Errorf("Failed to init servers: %s", err)
		return subcommands.ExitFailure
	}

	logger.Info("Checking sudo configuration... ")
	if err := scan.CheckIfSudoNoPasswd(logger); err != nil {
		logger.Errorf("Failed to sudo with nopassword via SSH. Define NOPASSWD in /etc/sudoers on target servers")
		return subcommands.ExitFailure
	}

	if errs := scan.Prepare(); 0 < len(errs) {
		for _, e := range errs {
			logger.Errorf("Failed to prepare: %s", e)
		}
		return subcommands.ExitFailure
	}

	return subcommands.ExitSuccess
}
