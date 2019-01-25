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
)

func Wpscan() (err error) {

	if err = wpscanVuln(); err != nil {
		return err
	}
	return
}

func wpscanVuln() (err error) {
	osTypeChan := make(chan error, len(config.Conf.Servers))
	defer close(osTypeChan)
	for _, s := range config.Conf.Wordpress {
		go func(s config.WpInfo) {
			defer func() {
				if p := recover(); p != nil {
					util.Log.Debugf("Panic: %s on %s", p, s.ServerName)
				}
			}()
			osTypeChan <- detectWp(s)
		}(s)
	}

	return
}

func detectWp(c config.WpInfo) (err error) {
	/*
	if r := exec(config.Conf.Wordpress, "wp core version --path=/home/kusanagi/yokota/DocumentRoot/", noSudo); r.isSuccess() {
	}
	*/
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
