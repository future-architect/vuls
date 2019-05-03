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
	"context"

	"golang.org/x/xerrors"

	"github.com/knqyf263/fanal/analyzer"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"

	// Register os and package analyzers
	_ "github.com/knqyf263/fanal/analyzer/os/alpine"
	_ "github.com/knqyf263/fanal/analyzer/os/amazonlinux"
	_ "github.com/knqyf263/fanal/analyzer/os/debian"
	_ "github.com/knqyf263/fanal/analyzer/os/opensuse"
	_ "github.com/knqyf263/fanal/analyzer/os/redhatbase"
	_ "github.com/knqyf263/fanal/analyzer/os/ubuntu"
	_ "github.com/knqyf263/fanal/analyzer/pkg/apk"
	_ "github.com/knqyf263/fanal/analyzer/pkg/dpkg"
	_ "github.com/knqyf263/fanal/analyzer/pkg/rpm"
)

// inherit OsTypeInterface
type staticContainer struct {
	base
}

func detectContainerImage(c config.ServerInfo) (itsMe bool, containerImage osTypeInterface, err error) {
	if c.Type != config.ServerTypeStaticContainer {
		return false, containerImage, nil
	}

	os, pkgs, err := scanImage(c)
	if err != nil {
		return false, containerImage, err
	}
	p := newContainerImage(c, pkgs)
	p.setDistro(os.Family, os.Name)
	return true, p, nil
}

// scanImage returns os, packages on image layers
func scanImage(c config.ServerInfo) (os *analyzer.OS, pkgs []analyzer.Package, err error) {
	if err = config.IsValidStaticContainerConf(c.StaticContainer); err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	domain := c.StaticContainer.Name + ":" + c.StaticContainer.Tag
	files, err := analyzer.Analyze(ctx, domain)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed scan files %q, %w", domain, err)
	}
	pkgs, err = analyzer.GetPackages(files)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed scan pkgs %q, %w", domain, err)
	}

	containerOs, err := analyzer.GetOS(files)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed scan os %q, %w", domain, err)
	}
	return &containerOs, pkgs, nil
}

func newContainerImage(c config.ServerInfo, pkgs []analyzer.Package) *staticContainer {
	modelPkgs := map[string]models.Package{}
	for _, pkg := range pkgs {
		modelPkgs[pkg.Name] = models.Package{
			Name:       pkg.Name,
			Release:    pkg.Release,
			Version:    pkg.Version,
			Repository: pkg.Type,
		}
	}
	d := &staticContainer{
		base: base{
			osPackages: osPackages{
				Packages:  modelPkgs,
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

func (o *staticContainer) checkScanMode() error {
	return nil
}

func (o *staticContainer) checkIfSudoNoPasswd() error {
	return nil
}

func (o *staticContainer) checkDeps() error {
	return nil
}

func (o *staticContainer) preCure() error {
	return nil
}

func (o *staticContainer) postScan() error {
	return nil
}

func (o *staticContainer) scanPackages() error {
	return nil
}

func (o *staticContainer) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}

func (o *staticContainer) detectPlatform() {
	o.setPlatform(models.Platform{Name: "staticContainer"})
	return
}
