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
func (c TOMLLoader) Load(pathToToml, keyPass string) (err error) {
	var conf Config
	if _, err := toml.DecodeFile(pathToToml, &conf); err != nil {
		log.Error("Load config failed", err)
		return err
	}

	Conf.Mail = conf.Mail
	Conf.Slack = conf.Slack

	d := conf.Default
	Conf.Default = d
	servers := make(map[string]ServerInfo)

	if keyPass != "" {
		d.KeyPassword = keyPass
	}

	i := 0
	for name, v := range conf.Servers {

		if 0 < len(v.KeyPassword) {
			log.Warn("[Deprecated] KEYPASSWORD IN CONFIG FILE ARE UNSECURE. REMOVE THEM IMMEDIATELY FOR A SECURITY REASONS. THEY WILL BE REMOVED IN A FUTURE RELEASE.")
		}

		s := ServerInfo{ServerName: name}

		switch {
		case v.User != "":
			s.User = v.User
		case d.User != "":
			s.User = d.User
		default:
			return fmt.Errorf("%s is invalid. User is empty", name)
		}

		s.Host = v.Host
		if s.Host == "" {
			return fmt.Errorf("%s is invalid. host is empty", name)
		}

		switch {
		case v.Port != "":
			s.Port = v.Port
		case d.Port != "":
			s.Port = d.Port
		default:
			s.Port = "22"
		}

		s.KeyPath = v.KeyPath
		if s.KeyPath == "" {
			s.KeyPath = d.KeyPath
		}
		if s.KeyPath != "" {
			if _, err := os.Stat(s.KeyPath); err != nil {
				return fmt.Errorf(
					"%s is invalid. keypath: %s not exists", name, s.KeyPath)
			}
		}

		//  s.KeyPassword = keyPass
		s.KeyPassword = v.KeyPassword
		if s.KeyPassword == "" {
			s.KeyPassword = d.KeyPassword
		}

		s.CpeNames = v.CpeNames
		if len(s.CpeNames) == 0 {
			s.CpeNames = d.CpeNames
		}

		s.Containers = v.Containers
		if len(s.Containers) == 0 {
			s.Containers = d.Containers
		}

		s.Optional = v.Optional
		for _, dkv := range d.Optional {
			found := false
			for _, kv := range s.Optional {
				if dkv[0] == kv[0] {
					found = true
					break
				}
			}
			if !found {
				s.Optional = append(s.Optional, dkv)
			}
		}

		s.LogMsgAnsiColor = Colors[i%len(Colors)]
		i++

		servers[name] = s
	}
	log.Debug("Config loaded")
	log.Debugf("%s", pp.Sprintf("%v", servers))
	Conf.Servers = servers
	return
}
