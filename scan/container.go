package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/aquasecurity/fanal/utils"
	"golang.org/x/xerrors"

	fanalos "github.com/aquasecurity/fanal/analyzer/os"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"

	// Register library analyzers
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"

	// Register os analyzers
	_ "github.com/aquasecurity/fanal/analyzer/os/alpine"
	_ "github.com/aquasecurity/fanal/analyzer/os/amazonlinux"
	_ "github.com/aquasecurity/fanal/analyzer/os/debianbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/redhatbase"
	_ "github.com/aquasecurity/fanal/analyzer/os/suse"

	// Register package analyzers
	_ "github.com/aquasecurity/fanal/analyzer/pkg/apk"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/dpkg"
	_ "github.com/aquasecurity/fanal/analyzer/pkg/rpmcmd"
)

// inherit OsTypeInterface
type image struct {
	base
}

// newDummyOS is constructor
func newDummyOS(c config.ServerInfo) *image {
	d := &image{
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

func detectContainerImage(c config.ServerInfo) (itsMe bool, containerImage osTypeInterface, err error) {
	if err = config.IsValidImage(c.Image); err != nil {
		return false, nil, nil
	}

	os, pkgs, libs, err := scanImage(c)
	if err != nil {
		// use Alpine for setErrs
		return false, newDummyOS(c), err
	}
	switch os.Family {
	case fanalos.OpenSUSELeap, fanalos.OpenSUSETumbleweed, fanalos.OpenSUSE:
		return false, newDummyOS(c), xerrors.Errorf("Unsupported OS : %s", os.Family)
	}

	libScanners, err := convertLibWithScanner(libs)
	if err != nil {
		return false, newDummyOS(c), err
	}

	osName := os.Name
	switch os.Family {
	case fanalos.Amazon:
		osName = "1"
		if strings.HasPrefix(os.Family, "2") {
			osName = "2"
		}
	}
	p := newContainerImage(c, pkgs, libScanners)
	p.setDistro(os.Family, osName)
	return true, p, nil
}

func convertLibWithScanner(libs map[analyzer.FilePath][]godeptypes.Library) ([]models.LibraryScanner, error) {
	scanners := []models.LibraryScanner{}
	for path, pkgs := range libs {
		scanners = append(scanners, models.LibraryScanner{Path: string(path), Libs: pkgs})
	}
	return scanners, nil
}

// scanImage returns os, packages on image layers
func scanImage(c config.ServerInfo) (os *analyzer.OS, pkgs []analyzer.Package, libs map[analyzer.FilePath][]godeptypes.Library, err error) {

	ctx := context.Background()
	domain := c.Image.GetFullName()
	util.Log.Info("Start fetch container... ", domain)

	fanalCache := cache.Initialize(utils.CacheDir())
	// Configure dockerOption
	dockerOption := c.Image.DockerOption
	if dockerOption.Timeout == 0 {
		dockerOption.Timeout = 60 * time.Second
	}
	ext, err := docker.NewDockerExtractor(dockerOption, fanalCache)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed initialize docker extractor%w", err)
	}
	ac := analyzer.Config{Extractor: ext}
	files, err := ac.Analyze(ctx, domain, dockerOption)

	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed scan files %q, %w", domain, err)
	}

	containerOs, err := analyzer.GetOS(files)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed scan os %q, %w", domain, err)
	}

	pkgs, err = analyzer.GetPackages(files)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed scan pkgs %q, %w", domain, err)
	}
	libs, err = analyzer.GetLibraries(files)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("Failed scan libs %q, %w", domain, err)
	}
	return &containerOs, pkgs, libs, nil
}

func convertFanalToVulsPkg(pkgs []analyzer.Package) (map[string]models.Package, map[string]models.SrcPackage) {
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
					Arch:        pkg.Arch,
					BinaryNames: []string{pkg.Name},
				}
			}
		}
	}
	return modelPkgs, modelSrcPkgs
}

func newContainerImage(c config.ServerInfo, pkgs []analyzer.Package, libs []models.LibraryScanner) *image {
	modelPkgs, modelSrcPkgs := convertFanalToVulsPkg(pkgs)
	d := &image{
		base: base{
			osPackages: osPackages{
				Packages:    modelPkgs,
				SrcPackages: modelSrcPkgs,
				VulnInfos:   models.VulnInfos{},
			},
			LibraryScanners: libs,
		},
	}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

func (o *image) checkScanMode() error {
	return nil
}

func (o *image) checkIfSudoNoPasswd() error {
	return nil
}

func (o *image) checkDeps() error {
	return nil
}

func (o *image) preCure() error {
	return nil
}

func (o *image) postScan() error {
	return nil
}

func (o *image) scanPackages() error {
	return nil
}

func (o *image) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}

func (o *image) detectPlatform() {
	o.setPlatform(models.Platform{Name: "image"})
}
