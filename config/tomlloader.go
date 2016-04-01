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

package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	"github.com/k0kubun/pp"
)

// TOMLLoader loads config
type TOMLLoader struct {
}

// Load load the configuraiton TOML file specified by path arg.
func (c TOMLLoader) Load(pathToToml string) (err error) {
	var conf Config
	if _, err := toml.DecodeFile(pathToToml, &conf); err != nil {
		log.Error("Load config failed.", err)
		return err
	}

	Conf.Mail = conf.Mail
	Conf.Slack = conf.Slack

	d := conf.Default
	Conf.Default = d
	servers := make(map[string]ServerInfo)

	i := 0
	for name, v := range conf.Servers {
		s := ServerInfo{ServerName: name}
		s.User = v.User
		if s.User == "" {
			s.User = d.User
		}

		s.Password = v.Password
		if s.Password == "" {
			s.Password = d.Password
		}

		s.Host = v.Host

		s.Port = v.Port
		if s.Port == "" {
			s.Port = d.Port
		}

		s.KeyPath = v.KeyPath
		if s.KeyPath == "" {
			s.KeyPath = d.KeyPath
		}
		if s.KeyPath != "" {
			if _, err := os.Stat(s.KeyPath); err != nil {
				return fmt.Errorf(
					"config.toml is invalid. keypath: %s not exists", s.KeyPath)
			}
		}

		s.KeyPassword = v.KeyPassword
		if s.KeyPassword == "" {
			s.KeyPassword = d.KeyPassword
		}

		s.CpeNames = v.CpeNames
		if len(s.CpeNames) == 0 {
			s.CpeNames = d.CpeNames
		}

		s.LogMsgAnsiColor = Colors[i%len(conf.Servers)]
		i++

		servers[name] = s
	}
	log.Debug("Config loaded.")
	log.Debugf("%s", pp.Sprintf("%v", servers))
	Conf.Servers = servers
	return
}
