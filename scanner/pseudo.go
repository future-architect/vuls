package scanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type pseudo struct {
	base
}

func detectPseudo(c config.ServerInfo) (itsMe bool, pseudo osTypeInterface, err error) {
	if c.Type == constant.ServerTypePseudo {
		p := newPseudo(c)
		p.setDistro(constant.ServerTypePseudo, "")
		return true, p, nil
	}
	return false, nil, nil
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
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

func (o *pseudo) checkScanMode() error {
	return nil
}

func (o *pseudo) checkIfSudoNoPasswd() error {
	return nil
}

func (o *pseudo) checkDeps() error {
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

func (o *pseudo) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}

func (o *pseudo) detectPlatform() {
	o.setPlatform(models.Platform{Name: "other"})
}

func (o *pseudo) scanLibraries() (err error) {
	if len(o.LibraryScanners) > 0 {
		return nil
	}

	// library scan for servers need lockfiles
	if len(o.getServerInfo().Lockfiles) == 0 && !o.getServerInfo().FindLock {
		return nil
	}

	o.log.Info("Scanning Language-specific Packages...")

	trivyLoggerInit()

	detectFiles := o.getServerInfo().Lockfiles

	if o.getServerInfo().FindLock {
		return xerrors.New("FindLock is not supported in pseudo")
	}

	found := make(map[string]bool)
	for _, path := range detectFiles {
		if path == "" {
			continue
		}

		abspath, err := filepath.Abs(path)
		if err != nil {
			return xerrors.Errorf("Failed to abs the lockfile. filepath: %s, err: %w", path, err)
		}

		if _, ok := found[abspath]; ok {
			continue
		}
		found[abspath] = true

		filemode, contents, err := func() (os.FileMode, []byte, error) {
			fileinfo, err := os.Stat(abspath)
			if err != nil {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to get target file info. filepath: %s, err: %w", abspath, err)
			}
			filemode := fileinfo.Mode().Perm()

			contents, err := os.ReadFile(abspath)
			if err != nil {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to read target file contents. filepath: %s, err: %w", abspath, err)
			}

			return filemode, contents, nil
		}()
		if err != nil {
			o.log.Warn(err)
			continue
		}

		trivypath := o.cleanPath(abspath)
		libraryScanners, err := AnalyzeLibrary(context.Background(), trivypath, contents, filemode, o.getServerInfo().Mode.IsOffline())
		if err != nil {
			return xerrors.Errorf("Failed to analyze library. err: %w, filepath: %s", err, trivypath)
		}
		for _, libscanner := range libraryScanners {
			libscanner.LockfilePath = abspath
			o.LibraryScanners = append(o.LibraryScanners, libscanner)
		}
	}

	return nil
}

// https://github.com/aquasecurity/trivy/blob/35e88890c3c201b3eb11f95376172e57bf44df4b/pkg/mapfs/fs.go#L272-L283
func (o *pseudo) cleanPath(path string) string {
	// Convert the volume name like 'C:' into dir like 'C\'
	if vol := filepath.VolumeName(path); vol != "" {
		newVol := strings.TrimSuffix(vol, ":")
		newVol = fmt.Sprintf("%s%c", newVol, filepath.Separator)
		path = strings.Replace(path, vol, newVol, 1)
	}
	path = filepath.Clean(path)
	path = filepath.ToSlash(path)
	path = strings.TrimLeft(path, "/") // Remove the leading slash
	return path
}
