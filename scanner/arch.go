package scanner

import (
	"bufio"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type arch struct {
	base
}

// NewArch constructor
func newArch(c config.ServerInfo) *arch {
	d := &arch{
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

func detectArch(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/arch-release", noSudo); !r.isSuccess() {
		logging.Log.Debugf("Not Arch Linux. %s", r)
		return false, nil
	}

	arch := newArch(c)
	arch.setDistro(constant.Arch, "")
	return true, arch
}

// lsof is needed to find open files.
// We will use it to determine which packages need restart.
func (o *arch) checkDeps() error {
	deps := []string{"lsof"}
	for _, cmd := range deps {
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			o.log.Warnf("%s is not installed", cmd)
			o.warns = append(o.warns, r.Error)
		}
	}
	o.log.Infof("Dependencies ... Pass")
	return nil
}

func (o *arch) checkScanMode() error {
	return nil
}

func (o *arch) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		o.log.Infof("sudo ... No need")
		return nil
	}

	cmds := []string{
		"stat /proc/1/exe",
		"ls -l /proc/1/exe",
		"cat /proc/1/maps",
	}

	for _, cmd := range cmds {
		cmd = util.PrependProxyEnv(cmd)
		o.log.Infof("Checking... sudo %s", cmd)
		if r := o.exec(cmd, sudo); !r.isSuccess() {
			o.log.Errorf("sudo error on %s", r)
			return xerrors.Errorf("Failed to sudo: %s", r)
		}
	}

	o.log.Infof("Sudo... Pass")
	return nil
}

func (o *arch) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	packs := models.Packages{}
	pkgInfos := strings.Split(stdout, "\n\n")
	for _, pkgInfo := range pkgInfos {
		if len(strings.TrimSpace(pkgInfo)) == 0 {
			continue
		}

		lines := strings.Split(pkgInfo, "\n")
		var name, version, release, arch string
		for _, line := range lines {
			columns := strings.Split(line, ":")
			leftColumn := strings.TrimSpace(columns[0])
			rightColumn := strings.TrimSpace(strings.Join(columns[1:], ":"))
			switch leftColumn {
			case "Name":
				name = rightColumn
			case "Version":
				values := strings.Split(rightColumn, "-")
				version = values[0]
				release = values[1]
			case "Architecture":
				arch = rightColumn
			}
		}

		packs[name] = models.Package{
			Name:    name,
			Version: version,
			Release: release,
			Arch:    arch,
		}
	}
	return packs, nil, nil
}

// TODO: Collect package names that needs reboot
func (o *arch) postScan() error {
	return nil
}

func (o *arch) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *arch) detectIPAddr() (err error) {
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

func (o *arch) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		err = xerrors.Errorf("Failed to scan updatable packages: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	} else {
		installed.MergeNewVersion(updatable)
	}

	o.Packages = installed
	return nil
}

func (o *arch) scanInstalledPackages() (models.Packages, error) {
	cmd := util.PrependProxyEnv("pacman -Qi")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	pkgs, _, _ := o.parseInstalledPackages(r.Stdout)

	return pkgs, nil
}

// TODO: Clean any traces
func (o *arch) scanUpdatablePackages() (models.Packages, error) {
	listOutdateCmd := `TMPPATH="${TMPDIR:-/tmp}/vuls"
DBPATH="$(pacman-conf DBPath)"

mkdir -p "$TMPPATH"
ln -s "$DBPATH/local" "$TMPPATH" &>/dev/null
fakeroot -- pacman -Sy --dbpath "$TMPPATH" --logfile /dev/null &>/dev/null
pacman -Qu --dbpath "$TMPPATH" 2>/dev/null
`
	cmd := util.PrependProxyEnv(listOutdateCmd)
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	pkgs, _ := o.parseOutdatedPackages(r.Stdout)

	unlinkCmd := `TMPPATH="${TMPDIR:-/tmp}/vuls"
rm -r "$TMPPATH"`

	cmd = util.PrependProxyEnv(unlinkCmd)
	r = o.exec(cmd, noSudo)
	if !r.isSuccess() {
		err := xerrors.Errorf("Failed to SSH: %s", r)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	}

	return pkgs, nil
}

func (o *arch) parseOutdatedPackages(stdout string) (models.Packages, error) {
	packs := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "->") {
			continue
		}
		ss := strings.Fields(line)
		name := ss[0]
		fullVersionInfo := ss[3]

		versionAndRelease := strings.Split(fullVersionInfo, "-")

		packs[name] = models.Package{
			Name:       name,
			NewVersion: versionAndRelease[0],
			NewRelease: versionAndRelease[1],
		}
	}
	return packs, nil
}
