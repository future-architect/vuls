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
	"os"

	"github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"golang.org/x/net/context"
)

// PrepareCmd is Subcommand of host discovery mode
type PrepareCmd struct {
	debug      bool
	configPath string

	useUnattendedUpgrades bool
}

// Name return subcommand name
func (*PrepareCmd) Name() string { return "prepare" }

// Synopsis return synopsis
func (*PrepareCmd) Synopsis() string {
	//  return "Install packages Ubuntu: unattended-upgrade, CentOS: yum-plugin-security)"
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
	prepare [-config=/path/to/config.toml] [-debug]

`
}

// SetFlags set flag
func (p *PrepareCmd) SetFlags(f *flag.FlagSet) {

	f.BoolVar(&p.debug, "debug", false, "debug mode")

	defaultConfPath := os.Getenv("PWD") + "/config.toml"
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	f.BoolVar(
		&p.useUnattendedUpgrades,
		"use-unattended-upgrades",
		false,
		"[Depricated] For Ubuntu, install unattended-upgrades",
	)
}

// Execute execute
func (p *PrepareCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	logrus.Infof("Begin Preparing (config: %s)", p.configPath)

	err := c.Load(p.configPath)
	if err != nil {
		logrus.Errorf("Error loading %s, %s", p.configPath, err)
		return subcommands.ExitUsageError
	}

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
	c.Conf.UseUnattendedUpgrades = p.useUnattendedUpgrades

	// Set up custom logger
	logger := util.NewCustomLogger(c.ServerInfo{})

	logger.Info("Detecting OS... ")
	err = scan.InitServers(logger)
	if err != nil {
		logger.Errorf("Failed to init servers. err: %s", err)
		return subcommands.ExitFailure
	}

	logger.Info("Installing...")
	if errs := scan.Prepare(); 0 < len(errs) {
		for _, e := range errs {
			logger.Errorf("Failed: %s", e)
		}
		return subcommands.ExitFailure
	}

	logger.Info("Success")
	return subcommands.ExitSuccess
}
