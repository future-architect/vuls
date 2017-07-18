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
	"github.com/future-architect/vuls/contrib/owasp-dependency-check/parser"
	log "github.com/sirupsen/logrus"
)

// TOMLLoader loads config
type TOMLLoader struct {
}

// Load load the configuraiton TOML file specified by path arg.
func (c TOMLLoader) Load(pathToToml, keyPass string) error {
	if Conf.Debug {
		log.SetLevel(log.DebugLevel)
	}

	var conf Config
	if _, err := toml.DecodeFile(pathToToml, &conf); err != nil {
		log.Error("Load config failed", err)
		return err
	}

	Conf.EMail = conf.EMail
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

		s.Host = v.Host
		if len(s.Host) == 0 {
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

		switch {
		case v.User != "":
			s.User = v.User
		case d.User != "":
			s.User = d.User
		default:
			if s.Port != "local" {
				return fmt.Errorf("%s is invalid. User is empty", name)
			}
		}

		s.KeyPath = v.KeyPath
		if len(s.KeyPath) == 0 {
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
		if len(s.KeyPassword) == 0 {
			s.KeyPassword = d.KeyPassword
		}

		s.CpeNames = v.CpeNames
		if len(s.CpeNames) == 0 {
			s.CpeNames = d.CpeNames
		}

		s.DependencyCheckXMLPath = v.DependencyCheckXMLPath
		if len(s.DependencyCheckXMLPath) == 0 {
			s.DependencyCheckXMLPath = d.DependencyCheckXMLPath
		}

		// Load CPEs from OWASP Dependency Check XML
		if len(s.DependencyCheckXMLPath) != 0 {
			cpes, err := parser.Parse(s.DependencyCheckXMLPath)
			if err != nil {
				return fmt.Errorf(
					"Failed to read OWASP Dependency Check XML: %s", err)
			}
			log.Debugf("Loaded from OWASP Dependency Check XML: %s",
				s.ServerName)
			s.CpeNames = append(s.CpeNames, cpes...)
		}

		s.Containers = v.Containers
		if len(s.Containers.Includes) == 0 {
			s.Containers = d.Containers
		}

		s.IgnoreCves = v.IgnoreCves
		for _, cve := range d.IgnoreCves {
			found := false
			for _, c := range s.IgnoreCves {
				if cve == c {
					found = true
					break
				}
			}
			if !found {
				s.IgnoreCves = append(s.IgnoreCves, cve)
			}
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

		s.Enablerepo = v.Enablerepo
		if len(s.Enablerepo) == 0 {
			s.Enablerepo = d.Enablerepo
		}
		if len(s.Enablerepo) != 0 {
			for _, repo := range s.Enablerepo {
				switch repo {
				case "base", "updates":
					// nop
				default:
					return fmt.Errorf(
						"For now, enablerepo have to be base or updates: %s, servername: %s",
						s.Enablerepo, name)
				}
			}
		}

		s.LogMsgAnsiColor = Colors[i%len(Colors)]
		i++

		servers[name] = s
	}
	Conf.Servers = servers
	return nil
}
