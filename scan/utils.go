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

package scan

import (
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/k0kubun/pp"
	"time"
)

func Wpscan() (err error) {
	if err = wpscanVuln(); err != nil {
		return err
	}
	return
}

func wpscanVuln() (err error) {
	errChan := make(chan error, len(config.Conf.Servers))
	defer close(errChan)
	for _, s := range config.Conf.Servers {
		go func(s config.ServerInfo) {
			defer func() {
				if p := recover(); p != nil {
					util.Log.Debugf("Panic: %s on %s", p, s.ServerName)
				}
			}()
			errChan <- detectWp(s)
		}(s)
	}

	timeout := time.After(time.Duration(10000) * time.Second)
	for i := 0; i < len(config.Conf.Servers); i++ {
		select {
		case _ = <-errChan:
		/*
			if 0 < len(res.getErrs()) {
				errServers = append(errServers, res)
				util.Log.Errorf("(%d/%d) Failed: %s, err: %s",
					i+1, len(config.Conf.Servers),
					res.getServerInfo().ServerName,
					res.getErrs())
			} else {
				servers = append(servers, res)
				util.Log.Infof("(%d/%d) Detected: %s: %s",
					i+1, len(config.Conf.Servers),
					res.getServerInfo().ServerName,
					res.getDistro())
			}
			*/
		case <-timeout:
			msg := "Timed out while detecting servers"
			util.Log.Error(msg)
			for servername, sInfo := range config.Conf.Servers {
				found := false
				for _, o := range append(servers, errServers...) {
					if servername == o.getServerInfo().ServerName {
						found = true
						break
					}
				}
				if !found {
					u := &unknown{}
					u.setServerInfo(sInfo)
					u.setErrs([]error{
						fmt.Errorf("Timed out"),
					})
					errServers = append(errServers, u)
					util.Log.Errorf("(%d/%d) Timed out: %s",
						i+1, len(config.Conf.Servers),
						servername)
					i++
				}
			}
		}
	}


	return
}

func detectWp(c config.ServerInfo) (err error) {
	if len(c.WordpressPath) != 0 {
		pp.Print("1")
	}
	cmd := fmt.Sprintf("wp core version --path=%s", c.WordpressToken)
	pp.Print(cmd)
	if r := exec(c, cmd, noSudo); r.isSuccess() {
		pp.Print(r.Stdout)
	}
	return err
}

func isRunningKernel(pack models.Package, family string, kernel models.Kernel) (isKernel, running bool) {
	switch family {
	case config.SUSEEnterpriseServer:
		if pack.Name == "kernel-default" {
			// Remove the last period and later because uname don't show that.
			ss := strings.Split(pack.Release, ".")
			rel := strings.Join(ss[0:len(ss)-1], ".")
			ver := fmt.Sprintf("%s-%s-default", pack.Version, rel)
			return true, kernel.Release == ver
		}
		return false, false

	case config.RedHat, config.Oracle, config.CentOS, config.Amazon:
		if pack.Name == "kernel" {
			ver := fmt.Sprintf("%s-%s.%s", pack.Version, pack.Release, pack.Arch)
			return true, kernel.Release == ver
		}
		return false, false

	default:
		util.Log.Warnf("Reboot required is not implemented yet: %s, %v", family, kernel)
	}
	return false, false
}

func rpmQa(distro config.Distro) string {
	const old = "rpm -qa --queryformat \"%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH}\n\""
	const new = "rpm -qa --queryformat \"%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH}\n\""
	switch distro.Family {
	case config.SUSEEnterpriseServer:
		if v, _ := distro.MajorVersion(); v < 12 {
			return old
		}
		return new
	default:
		if v, _ := distro.MajorVersion(); v < 6 {
			return old
		}
		return new
	}
}
