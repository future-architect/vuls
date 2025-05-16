package scanner

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ufilepath "github.com/future-architect/vuls/scanner/utils/filepath"
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
	if len(o.ServerInfo.Lockfiles) == 0 && !o.ServerInfo.FindLock {
		return nil
	}

	shell := func() string {
		if r := o.exec("uname", noSudo); r.isSuccess() {
			return "linux/unix"
		}

		if r := o.exec("echo $env:OS", noSudo); r.isSuccess() {
			switch strings.TrimSpace(r.Stdout) {
			case "$env:OS":
				return "cmd.exe"
			case "Windows_NT":
				return "powershell"
			default:
				if r := o.exec("Get-ChildItem env:OS", noSudo); r.isSuccess() {
					return "powershell"
				}
				return "unknown"
			}
		}
		return "unknown"
	}()

	o.log.Info("Scanning Language-specific Packages...")

	trivyLoggerInit()

	detectFiles := o.ServerInfo.Lockfiles

	priv := noSudo
	if o.getServerInfo().Mode.IsFastRoot() || o.getServerInfo().Mode.IsDeep() {
		priv = sudo
	}

	// auto detect lockfile
	if o.ServerInfo.FindLock {
		cmd := func() string {
			switch shell {
			case "cmd.exe":
				dir := func() string {
					if len(o.ServerInfo.FindLockDirs) == 0 {
						o.log.Infof("It's recommended to specify FindLockDirs in config.toml. If FindLockDirs is not specified, all directories under / will be searched, which may increase CPU load")
						return "C:\\"
					}

					ss := make([]string, 0, len(o.ServerInfo.FindLockDirs))
					for _, d := range o.ServerInfo.FindLockDirs {
						if strings.HasSuffix(d, "\\") {
							d = fmt.Sprintf("%s\\", d)
						}
						ss = append(ss, fmt.Sprintf("\\\"%s\\\"", d))
					}
					return strings.Join(ss, ",")
				}()

				findopt := func() string {
					ss := make([]string, 0, len(models.FindLockFiles))
					for _, filename := range models.FindLockFiles {
						ss = append(ss, fmt.Sprintf("\\\"%s\\\"", filename))
					}
					return strings.Join(ss, ", ")
				}()

				o.log.Infof("Finding files under %s", dir)

				// powershell.exe -NoProfile -NonInteractive "Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @(\"package-lock.json\", \"yarn.lock\") } | Select-Object -ExpandProperty FullName"
				return fmt.Sprintf("powershell.exe -NoProfile -NonInteractive %q", strings.ReplaceAll(fmt.Sprintf("Get-ChildItem -Path %s -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @(%s) } | Select-Object -ExpandProperty FullName", dir, findopt), `"`, `\"`))
			case "powershell":
				dir := func() string {
					if len(o.ServerInfo.FindLockDirs) == 0 {
						o.log.Infof("It's recommended to specify FindLockDirs in config.toml. If FindLockDirs is not specified, all directories under / will be searched, which may increase CPU load")
						return "C:\\"
					}

					ss := make([]string, 0, len(o.ServerInfo.FindLockDirs))
					for _, d := range o.ServerInfo.FindLockDirs {
						ss = append(ss, fmt.Sprintf("%q", d))
					}
					return strings.Join(ss, ",")
				}()

				findopt := func() string {
					ss := make([]string, 0, len(models.FindLockFiles))
					for _, filename := range models.FindLockFiles {
						ss = append(ss, fmt.Sprintf("%q", filename))
					}
					return strings.Join(ss, ", ")
				}()

				o.log.Infof("Finding files under %s", dir)

				// Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @("package-lock.json", "yarn.lock") } | Select-Object -ExpandProperty FullName
				return fmt.Sprintf("Get-ChildItem -Path %s -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in @(%s) } | Select-Object -ExpandProperty FullName", dir, findopt)
			default:
				dir := func() string {
					if len(o.ServerInfo.FindLockDirs) == 0 {
						o.log.Infof("It's recommended to specify FindLockDirs in config.toml. If FindLockDirs is not specified, all directories under / will be searched, which may increase CPU load")
						return "/"
					}
					return strings.Join(o.ServerInfo.FindLockDirs, " ")
				}()

				findopt := func() string {
					ss := make([]string, 0, len(models.FindLockFiles))
					for _, filename := range models.FindLockFiles {
						ss = append(ss, fmt.Sprintf("-name %q", filename))
					}
					return strings.Join(ss, " -o ")
				}()

				o.log.Infof("Finding files under %s", dir)

				// find / -type f -and \( -name "package-lock.json" -o -name "yarn.lock" ... \) 2>&1 | grep -v "find: "
				return fmt.Sprintf(`find %s -type f -and \( `+findopt[:len(findopt)-3]+` \) 2>&1 | grep -v "find: "`, dir)
			}
		}()

		r := exec(o.ServerInfo, cmd, priv)
		if r.ExitStatus != 0 && r.ExitStatus != 1 {
			return xerrors.Errorf("Failed to find lock files")
		}
		detectFiles = append(detectFiles, strings.Split(r.Stdout, "\n")...)
	}

	wd := func() string {
		switch shell {
		case "cmd.exe":
			if r := o.exec("powershell.exe -NoProfile -NonInteractive \"Get-Location | Select-object -ExpandProperty Path\"", noSudo); r.isSuccess() {
				return strings.TrimSpace(r.Stdout)
			}
			return "C:\\"
		case "powershell":
			if r := o.exec("Get-Location | Select-object -ExpandProperty Path", noSudo); r.isSuccess() {
				return strings.TrimSpace(r.Stdout)
			}
			return "C:\\"
		default:
			if r := o.exec("pwd", noSudo); r.isSuccess() {
				return strings.TrimSpace(r.Stdout)
			}
			return "/"
		}
	}()

	found := make(map[string]bool)
	for _, path := range detectFiles {
		if path == "" {
			continue
		}

		abspath := func() string {
			switch shell {
			case "cmd.exe", "powershell":
				return ufilepath.WindowsAbs(wd, path)
			default:
				return ufilepath.UnixAbs(wd, path)
			}
		}()

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

		libraryScanners, err := AnalyzeLibrary(context.Background(), abspath, contents, filemode, o.ServerInfo.Mode.IsOffline())
		if err != nil {
			return xerrors.Errorf("Failed to analyze library. err: %w, filepath: %s", err, abspath)
		}
		o.LibraryScanners = append(o.LibraryScanners, libraryScanners...)
	}

	return nil
}
