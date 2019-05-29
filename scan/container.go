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
	"fmt"
	"time"

	"github.com/knqyf263/fanal/analyzer"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	fanalos "github.com/knqyf263/fanal/analyzer/os"

	// Register os and package analyzers
	_ "github.com/knqyf263/fanal/analyzer/os/alpine"
	_ "github.com/knqyf263/fanal/analyzer/os/amazonlinux"
	_ "github.com/knqyf263/fanal/analyzer/os/debianbase"
	_ "github.com/knqyf263/fanal/analyzer/os/opensuse"
	_ "github.com/knqyf263/fanal/analyzer/os/redhatbase"
	_ "github.com/knqyf263/fanal/analyzer/pkg/apk"
	_ "github.com/knqyf263/fanal/analyzer/pkg/dpkg"
	_ "github.com/knqyf263/fanal/analyzer/pkg/rpmcmd"
)

// inherit OsTypeInterface
type containerImage struct {
	base
}

func detectContainerImage(c config.ServerInfo) (itsMe bool, containerImage osTypeInterface, err error) {
	os, pkgs, err := scanImage(c)
	if err != nil {
		// use Alpine for setErrs
		containerImage = newAlpine(c)
		return false, containerImage, err
	}
	switch os.Family {
	case fanalos.OpenSUSELeap, fanalos.OpenSUSETumbleweed, fanalos.OpenSUSE:
		containerImage = newAlpine(c)
		return false, containerImage, xerrors.Errorf("Unsupported OS : %s", os.Family)
	}

	p := newContainerImage(c, pkgs)
	p.setDistro(os.Family, os.Name)
	return true, p, nil
}

// scanImage returns os, packages on image layers
func scanImage(c config.ServerInfo) (os *analyzer.OS, pkgs []analyzer.Package, err error) {
	if err = config.IsValidImage(c.Image); err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	domain := c.Image.Name + ":" + c.Image.Tag
	util.Log.Info("Start fetch container... ", domain)

	// Configure dockerOption
	dockerOption := c.Image.DockerOption
	if dockerOption.Timeout == 0 {
		dockerOption.Timeout = 600 * time.Second
	}
	files, err := analyzer.Analyze(ctx, domain, dockerOption)

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

func newContainerImage(c config.ServerInfo, pkgs []analyzer.Package) *containerImage {
	modelPkgs := map[string]models.Package{}
	modelSrcPkgs := map[string]models.SrcPackage{}
	for _, pkg := range pkgs {
		version := pkg.Version
		if pkg.Epoch != 0 {
			version = fmt.Sprintf("%d:%s", pkg.Epoch, pkg.Version)
		}
		modelPkgs[pkg.Name] = models.Package{
			Name:    pkg.Name,
			Release: pkg.Release,
			Version: version,
			Arch:    pkg.Arch,
		}

		// add SrcPacks
		if pkg.Name != pkg.SrcName {
			if pack, ok := modelSrcPkgs[pkg.SrcName]; ok {
				pack.AddBinaryName(pkg.Name)
				modelSrcPkgs[pkg.SrcName] = pack
			} else {
				modelSrcPkgs[pkg.SrcName] = models.SrcPackage{
					Name:        pkg.SrcName,
					Version:     pkg.SrcVersion,
					BinaryNames: []string{pkg.Name},
				}
			}
		}
	}
	d := &containerImage{
		base: base{
			osPackages: osPackages{
				Packages:    modelPkgs,
				SrcPackages: modelSrcPkgs,
				VulnInfos:   models.VulnInfos{},
			},
		},
	}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

func (o *containerImage) checkScanMode() error {
	return nil
}

func (o *containerImage) checkIfSudoNoPasswd() error {
	return nil
}

func (o *containerImage) checkDeps() error {
	return nil
}

func (o *containerImage) preCure() error {
	return nil
}

func (o *containerImage) postScan() error {
	return nil
}

func (o *containerImage) scanPackages() error {
	return nil
}

func (o *containerImage) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}

func (o *containerImage) detectPlatform() {
	o.setPlatform(models.Platform{Name: "image"})
}
