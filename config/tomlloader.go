/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/knqyf263/go-cpe/naming"
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
	Conf.Saas = conf.Saas
	Conf.Syslog = conf.Syslog
	Conf.HTTP = conf.HTTP
	Conf.AWS = conf.AWS
	Conf.Azure = conf.Azure

	Conf.CveDict = conf.CveDict
	Conf.OvalDict = conf.OvalDict
	Conf.Gost = conf.Gost

	d := conf.Default
	Conf.Default = d
	servers := make(map[string]ServerInfo)

	if keyPass != "" {
		d.KeyPassword = keyPass
	}

	i := 0
	for serverName, v := range conf.Servers {
		if 0 < len(v.KeyPassword) {
			return fmt.Errorf("[Deprecated] KEYPASSWORD IN CONFIG FILE ARE UNSECURE. REMOVE THEM IMMEDIATELY FOR A SECURITY REASONS. THEY WILL BE REMOVED IN A FUTURE RELEASE: %s", serverName)
		}

		s := ServerInfo{ServerName: serverName}
		if v.Type != ServerTypePseudo {
			s.Host = v.Host
			if len(s.Host) == 0 {
				return fmt.Errorf("%s is invalid. host is empty", serverName)
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
					return fmt.Errorf("%s is invalid. User is empty", serverName)
				}
			}

			s.KeyPath = v.KeyPath
			if len(s.KeyPath) == 0 {
				s.KeyPath = d.KeyPath
			}
			if s.KeyPath != "" {
				if _, err := os.Stat(s.KeyPath); err != nil {
					return fmt.Errorf(
						"%s is invalid. keypath: %s not exists", serverName, s.KeyPath)
				}
			}

			s.KeyPassword = v.KeyPassword
			if len(s.KeyPassword) == 0 {
				s.KeyPassword = d.KeyPassword
			}
		}

		s.ScanMode = v.ScanMode
		if len(s.ScanMode) == 0 {
			s.ScanMode = d.ScanMode
			if len(s.ScanMode) == 0 {
				s.ScanMode = []string{"fast"}
			}
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
				return fmt.Errorf("scanMode: %s of %s is invalie. Specify -fast, -fast-root, -deep or offline", m, serverName)
			}
		}
		if err := s.Mode.validate(); err != nil {
			return fmt.Errorf("%s in %s", err, serverName)
		}

		s.CpeNames = v.CpeNames
		if len(s.CpeNames) == 0 {
			s.CpeNames = d.CpeNames
		}

		for i, n := range s.CpeNames {
			uri, err := toCpeURI(n)
			if err != nil {
				return fmt.Errorf("Failed to parse CPENames %s in %s: %s", n, serverName, err)
			}
			s.CpeNames[i] = uri
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
		for contName, cont := range s.Containers {
			cont.IgnoreCves = append(cont.IgnoreCves, d.IgnoreCves...)
			s.Containers[contName] = cont
		}

		if len(v.DependencyCheckXMLPath) != 0 || len(d.DependencyCheckXMLPath) != 0 {
			return fmt.Errorf("[DEPRECATED] dependencyCheckXMLPath IS DEPRECATED. USE owaspDCXMLPath INSTEAD: %s", serverName)
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

		s.IgnorePkgsRegexp = v.IgnorePkgsRegexp
		for _, pkg := range d.IgnorePkgsRegexp {
			found := false
			for _, p := range s.IgnorePkgsRegexp {
				if pkg == p {
					found = true
					break
				}
			}
			if !found {
				s.IgnorePkgsRegexp = append(s.IgnorePkgsRegexp, pkg)
			}
		}
		for _, reg := range s.IgnorePkgsRegexp {
			_, err := regexp.Compile(reg)
			if err != nil {
				return fmt.Errorf("Faild to parse %s in %s. err: %s", reg, serverName, err)
			}
		}
		for contName, cont := range s.Containers {
			for _, reg := range cont.IgnorePkgsRegexp {
				_, err := regexp.Compile(reg)
				if err != nil {
					return fmt.Errorf("Faild to parse %s in %s@%s. err: %s",
						reg, contName, serverName, err)
				}
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
						s.Enablerepo, serverName)
				}
			}
		}

		s.UUIDs = v.UUIDs
		s.Type = v.Type

		s.LogMsgAnsiColor = Colors[i%len(Colors)]
		i++

		servers[serverName] = s
	}
	Conf.Servers = servers
	return nil
}

func toCpeURI(cpename string) (string, error) {
	if strings.HasPrefix(cpename, "cpe:2.3:") {
		wfn, err := naming.UnbindFS(cpename)
		if err != nil {
			return "", err
		}
		return naming.BindToURI(wfn), nil
	} else if strings.HasPrefix(cpename, "cpe:/") {
		wfn, err := naming.UnbindURI(cpename)
		if err != nil {
			return "", err
		}
		return naming.BindToURI(wfn), nil
	}
	return "", fmt.Errorf("Unknow CPE format: %s", cpename)
}
