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

package scan

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type pseudo struct {
	base
}

func detectPseudo(c config.ServerInfo) (itsMe bool, pseudo osTypeInterface, err error) {
	p := newPseudo(c)
	p.setDistro(config.ServerTypePseudo, "")
	return c.Type == config.ServerTypePseudo, p, nil
}

func newPseudo(c config.ServerInfo) *pseudo {
	d := &pseudo{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

func (o *pseudo) checkIfSudoNoPasswd() error {
	return nil
}

func (o *pseudo) checkDependencies() error {
	return nil
}

func (o *pseudo) preCure() error {
	return nil
}

func (o *pseudo) postScan() error {
	return nil
}

func (o *pseudo) scanPackages() error {
	return nil
}

func (o *pseudo) detectPlatform() {
	o.setPlatform(models.Platform{Name: "other"})
	return
}
