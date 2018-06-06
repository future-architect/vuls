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
)

// TOMLLoader loads config
type TOMLLoader struct {
}

// Load load the configuration TOML file specified by path arg.
func (c TOMLLoader) Load(pathToToml, keyPass string) error {
	var conf Config
	if _, err := toml.DecodeFile(pathToToml, &conf); err != nil {
		return err
	}
	Conf.EMail = conf.EMail
	Conf.Slack = conf.Slack
	Conf.Stride = conf.Stride
	Conf.HipChat = conf.HipChat
	Conf.ChatWork = conf.ChatWork
	Conf.Syslog = conf.Syslog

	d := conf.Default
	Conf.Default = d
	servers := make(map[string]ServerInfo)

	if keyPass != "" {
		d.KeyPassword = keyPass
	}

	i := 0
	for name, v := range conf.Servers {
		if 0 < len(v.KeyPassword) {
			return fmt.Errorf("[Deprecated] KEYPASSWORD IN CONFIG FILE ARE UNSECURE. REMOVE THEM IMMEDIATELY FOR A SECURITY REASONS. THEY WILL BE REMOVED IN A FUTURE RELEASE: %s", name)
		}

		s := ServerInfo{ServerName: name}

		if v.Type != ServerTypePseudo {
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
		}

		s.ScanMode = v.ScanMode
		if len(s.ScanMode) == 0 {
			s.ScanMode = d.ScanMode
		}
		for _, m := range s.ScanMode {
			switch m {
			case "fast":
				s.Mode.Set(Fast)
			case "fast-root":
				s.Mode.Set(FastRoot)
			case "deep":
				s.Mode.Set(Deep)
			case "offline":
				s.Mode.Set(Offline)
			default:
				return fmt.Errorf("scanMode: %s of %s is invalie. Specify -fast, -fast-root, -deep or offline", m, name)
			}
		}
		if err := s.Mode.validate(); err != nil {
			return fmt.Errorf("%s in %s", err, name)
		}

		if len(v.CpeNames) != 0 || len(d.CpeNames) != 0 {
			return fmt.Errorf("[DEPRECATED] cpeNames IS DEPRECATED. USE cpeURIs INSTEAD: %s", name)
		}

		s.CpeURIs = v.CpeURIs
		if len(s.CpeURIs) == 0 {
			s.CpeURIs = d.CpeURIs
		}

		s.ContainersIncluded = v.ContainersIncluded
		if len(s.ContainersIncluded) == 0 {
			s.ContainersIncluded = d.ContainersIncluded
		}

		s.ContainersExcluded = v.ContainersExcluded
		if len(s.ContainersExcluded) == 0 {
			s.ContainersExcluded = d.ContainersExcluded
		}

		s.ContainerType = v.ContainerType
		if len(s.ContainerType) == 0 {
			s.ContainerType = d.ContainerType
		}

		s.Containers = v.Containers
		if len(s.Containers) == 0 {
			s.Containers = d.Containers
		}

		if len(v.DependencyCheckXMLPath) != 0 || len(d.DependencyCheckXMLPath) != 0 {
			return fmt.Errorf("[DEPRECATED] dependencyCheckXMLPath IS DEPRECATED. USE owaspDCXMLPath INSTEAD: %s", name)
		}

		s.OwaspDCXMLPath = v.OwaspDCXMLPath
		if len(s.OwaspDCXMLPath) == 0 {
			s.OwaspDCXMLPath = d.OwaspDCXMLPath
		}

		s.Memo = v.Memo
		if s.Memo == "" {
			s.Memo = d.Memo
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

		opt := map[string]interface{}{}
		for k, v := range d.Optional {
			opt[k] = v
		}
		for k, v := range v.Optional {
			opt[k] = v
		}
		s.Optional = opt

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

		s.UUIDs = v.UUIDs
		s.Type = v.Type

		s.LogMsgAnsiColor = Colors[i%len(Colors)]
		i++

		servers[name] = s
	}
	Conf.Servers = servers
	return nil
}
