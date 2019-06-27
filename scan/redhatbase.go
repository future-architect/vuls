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
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"

	ver "github.com/knqyf263/go-rpm-version"
)

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		util.Log.Warnf("Fedora not tested yet: %s", r)
		return true, &unknown{}
	}

	if r := exec(c, "ls /etc/oracle-release", noSudo); r.isSuccess() {
		// Need to discover Oracle Linux first, because it provides an
		// /etc/redhat-release that matches the upstream distribution
		if r := exec(c, "cat /etc/oracle-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				util.Log.Warnf("Failed to parse Oracle Linux version: %s", r)
				return true, newOracle(c)
			}

			ora := newOracle(c)
			release := result[2]
			ora.setDistro(config.Oracle, release)
			return true, ora
		}
	}

	// https://bugzilla.redhat.com/show_bug.cgi?id=1332025
	// CentOS cloud image
	if r := exec(c, "ls /etc/centos-release", noSudo); r.isSuccess() {
		if r := exec(c, "cat /etc/centos-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				util.Log.Warnf("Failed to parse CentOS version: %s", r)
				return true, newCentOS(c)
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				cent := newCentOS(c)
				cent.setDistro(config.CentOS, release)
				return true, cent
			default:
				util.Log.Warnf("Failed to parse CentOS: %s", r)
			}
		}
	}

	if r := exec(c, "ls /etc/redhat-release", noSudo); r.isSuccess() {
		// https://www.rackaid.com/blog/how-to-determine-centos-or-red-hat-version/
		// e.g.
		// $ cat /etc/redhat-release
		// CentOS release 6.5 (Final)
		if r := exec(c, "cat /etc/redhat-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				util.Log.Warnf("Failed to parse RedHat/CentOS version: %s", r)
				return true, newCentOS(c)
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				cent := newCentOS(c)
				cent.setDistro(config.CentOS, release)
				return true, cent
			default:
				// RHEL
				rhel := newRHEL(c)
				rhel.setDistro(config.RedHat, release)
				return true, rhel
			}
		}
	}

	if r := exec(c, "ls /etc/system-release", noSudo); r.isSuccess() {
		family := config.Amazon
		release := "unknown"
		if r := exec(c, "cat /etc/system-release", noSudo); r.isSuccess() {
			if strings.HasPrefix(r.Stdout, "Amazon Linux release 2") {
				fields := strings.Fields(r.Stdout)
				release = fmt.Sprintf("%s %s", fields[3], fields[4])
			} else if strings.HasPrefix(r.Stdout, "Amazon Linux 2") {
				fields := strings.Fields(r.Stdout)
				release = strings.Join(fields[2:], " ")
			} else {
				fields := strings.Fields(r.Stdout)
				if len(fields) == 5 {
					release = fields[4]
				}
			}
		}
		amazon := newAmazon(c)
		amazon.setDistro(family, release)
		return true, amazon
	}

	util.Log.Debugf("Not RedHat like Linux. servername: %s", c.ServerName)
	return false, &unknown{}
}

// inherit OsTypeInterface
type redhatBase struct {
	base
	sudo rootPriv
}

type rootPriv interface {
	repoquery() bool
	yumMakeCache() bool
	yumPS() bool
}

type cmd struct {
	cmd                 string
	expectedStatusCodes []int
}

var exitStatusZero = []int{0}

func (o *redhatBase) execCheckIfSudoNoPasswd(cmds []cmd) error {
	for _, c := range cmds {
		cmd := util.PrependProxyEnv(c.cmd)
		o.log.Infof("Checking... sudo %s", cmd)
		r := o.exec(util.PrependProxyEnv(cmd), sudo)
		if !r.isSuccess(c.expectedStatusCodes...) {
			o.log.Errorf("Check sudo or proxy settings: %s", r)
			return xerrors.Errorf("Failed to sudo: %s", r)
		}
	}
	o.log.Infof("Sudo... Pass")
	return nil
}

func (o *redhatBase) execCheckDeps(packNames []string) error {
	for _, name := range packNames {
		cmd := "rpm -q " + name
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("%s is not installed", name)
			o.log.Errorf(msg)
			return xerrors.New(msg)
		}
	}
	o.log.Infof("Dependencies ... Pass")
	return nil
}

func (o *redhatBase) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *redhatBase) postScan() error {
	//TODO
	o.yumPsUshida()

	if o.isExecYumPS() {
		if err := o.yumPS(); err != nil {
			err = xerrors.Errorf("Failed to execute yum-ps: %w", err)
			o.log.Warnf("err: %+v", err)
			o.warns = append(o.warns, err)
			// Only warning this error
		}
	}

	if o.isExecNeedsRestarting() {
		if err := o.needsRestarting(); err != nil {
			err = xerrors.Errorf("Failed to execute need-restarting: %w", err)
			o.log.Warnf("err: %+v", err)
			o.warns = append(o.warns, err)
			// Only warning this error
		}
	}
	return nil
}

func (o *redhatBase) detectIPAddr() (err error) {
	o.log.Infof("Scanning in %s", o.getServerInfo().Mode)
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

func (o *redhatBase) scanPackages() error {
	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	o.Packages = installed

	rebootRequired, err := o.rebootRequired()
	if err != nil {
		err = xerrors.Errorf("Failed to detect the kernel reboot required: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	} else {
		o.Kernel.RebootRequired = rebootRequired
	}

	if o.getServerInfo().Mode.IsOffline() {
		return nil
	} else if o.Distro.Family == config.RedHat {
		if o.getServerInfo().Mode.IsFast() {
			return nil
		}
	}

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		err = xerrors.Errorf("Failed to scan updatable packages: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	} else {
		installed.MergeNewVersion(updatable)
		o.Packages = installed
	}
	return nil
}

func (o *redhatBase) rebootRequired() (bool, error) {
	r := o.exec("rpm -q --last kernel", noSudo)
	scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
	if !r.isSuccess(0, 1) {
		return false, xerrors.Errorf("Failed to detect the last installed kernel : %v", r)
	}
	if !r.isSuccess() || !scanner.Scan() {
		return false, nil
	}
	lastInstalledKernelVer := strings.Fields(scanner.Text())[0]
	running := fmt.Sprintf("kernel-%s", o.Kernel.Release)
	return running != lastInstalledKernelVer, nil
}

func (o *redhatBase) scanInstalledPackages() (models.Packages, error) {
	release, version, err := o.runningKernel()
	if err != nil {
		return nil, err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	r := o.exec(rpmQa(o.Distro), noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Scan packages failed: %s", r)
	}
	installed, _, err := o.parseInstalledPackages(r.Stdout)
	if err != nil {
		return nil, err
	}
	return installed, nil
}

func (o *redhatBase) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	installed := models.Packages{}
	latestKernelRelease := ver.NewVersion("")

	// openssl 0 1.0.1e	30.el6.11 x86_64
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if trimed := strings.TrimSpace(line); len(trimed) != 0 {
			pack, err := o.parseInstalledPackagesLine(line)
			if err != nil {
				return nil, nil, err
			}

			// Kernel package may be isntalled multiple versions.
			// From the viewpoint of vulnerability detection,
			// pay attention only to the running kernel
			isKernel, running := isRunningKernel(pack, o.Distro.Family, o.Kernel)
			if isKernel {
				if o.Kernel.Release == "" {
					// When the running kernel release is unknown,
					// use the latest release among the installed release
					kernelRelease := ver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
					if kernelRelease.LessThan(latestKernelRelease) {
						continue
					}
					latestKernelRelease = kernelRelease
				} else if !running {
					o.log.Debugf("Not a running kernel. pack: %#v, kernel: %#v", pack, o.Kernel)
					continue
				} else {
					o.log.Debugf("Found a running kernel. pack: %#v, kernel: %#v", pack, o.Kernel)
				}
			}
			installed[pack.Name] = pack
		}
	}
	return installed, nil, nil
}

func (o *redhatBase) parseInstalledPackagesLine(line string) (models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return models.Package{},
			xerrors.Errorf("Failed to parse package line: %s", line)
	}
	ver := ""
	epoch := fields[1]
	if epoch == "0" || epoch == "(none)" {
		ver = fields[2]
	} else {
		ver = fmt.Sprintf("%s:%s", epoch, fields[2])
	}

	return models.Package{
		Name:    fields[0],
		Version: ver,
		Release: fields[3],
		Arch:    fields[4],
	}, nil
}

func (o *redhatBase) yumMakeCache() error {
	cmd := `yum makecache`
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumMakeCache())
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to SSH: %s", r)
	}
	return nil
}

func (o *redhatBase) scanUpdatablePackages() (models.Packages, error) {
	if err := o.yumMakeCache(); err != nil {
		return nil, xerrors.Errorf("Failed to `yum makecache`: %w", err)
	}

	isDnf := o.exec(util.PrependProxyEnv(`repoquery --version | grep dnf`), o.sudo.repoquery()).isSuccess()
	cmd := `repoquery --all --pkgnarrow=updates --qf='%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{REPO}'`
	if isDnf {
		cmd = `repoquery --upgrades --qf='%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{REPONAME}' -q`
	}
	for _, repo := range o.getServerInfo().Enablerepo {
		cmd += " --enablerepo=" + repo
	}

	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.repoquery())
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}

	// Collect Updateble packages, installed, candidate version and repository.
	return o.parseUpdatablePacksLines(r.Stdout)
}

// parseUpdatablePacksLines parse the stdout of repoquery to get package name, candidate version
func (o *redhatBase) parseUpdatablePacksLines(stdout string) (models.Packages, error) {
	updatable := models.Packages{}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		// TODO remove
		// if strings.HasPrefix(line, "Obsoleting") ||
		// strings.HasPrefix(line, "Security:") {
		// // see https://github.com/future-architect/vuls/issues/165
		// continue
		// }
		if len(strings.TrimSpace(line)) == 0 {
			continue
		} else if strings.HasPrefix(line, "Loading") {
			continue
		}
		pack, err := o.parseUpdatablePacksLine(line)
		if err != nil {
			return updatable, err
		}
		updatable[pack.Name] = pack
	}
	return updatable, nil
}

func (o *redhatBase) parseUpdatablePacksLine(line string) (models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return models.Package{}, xerrors.Errorf("Unknown format: %s, fields: %s", line, fields)
	}

	ver := ""
	epoch := fields[1]
	if epoch == "0" {
		ver = fields[2]
	} else {
		ver = fmt.Sprintf("%s:%s", epoch, fields[2])
	}

	repos := strings.Join(fields[4:], " ")

	p := models.Package{
		Name:       fields[0],
		NewVersion: ver,
		NewRelease: fields[3],
		Repository: repos,
	}
	return p, nil
}

func (o *redhatBase) isExecYumPS() bool {
	switch o.Distro.Family {
	case
		config.OpenSUSE,
		config.OpenSUSELeap,
		config.SUSEEnterpriseServer,
		config.SUSEEnterpriseDesktop,
		config.SUSEOpenstackCloud:
		return false
	case config.RedHat:
		// RHEL8 dnf doesn't have yum-pulgin-ps
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil || 8 < majorVersion {
			o.log.Errorf("yum ps Not implemented yet: %s, err: %s", o.Distro, err)
			return false
		}
	}

	// yum ps needs internet connection
	if o.getServerInfo().Mode.IsOffline() || o.getServerInfo().Mode.IsFast() {
		return false
	}
	return true
}

func (o *redhatBase) isExecNeedsRestarting() bool {
	switch o.Distro.Family {
	case config.OpenSUSE,
		config.OpenSUSELeap,
		config.SUSEEnterpriseServer,
		config.SUSEEnterpriseDesktop,
		config.SUSEOpenstackCloud:
		// TODO zypper ps
		// https://github.com/future-architect/vuls/issues/696
		return false
	case config.RedHat, config.CentOS, config.Oracle:
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil || majorVersion < 6 {
			o.log.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
			return false
		}

		if o.getServerInfo().Mode.IsOffline() {
			return false
		} else if o.getServerInfo().Mode.IsFastRoot() ||
			o.getServerInfo().Mode.IsDeep() {
			return true
		}
		return false
	}

	if o.getServerInfo().Mode.IsFast() {
		return false
	}
	return true
}

type loadedFile struct {
	pid      string
	procName string
	path     string
	pkgName  string
}

func (o *redhatBase) yumPsUshida() error {
	stdout, err := o.ps()
	if err != nil {
		// TODO wrap
		return err
	}
	pidNames := o.parsePs(stdout)

	loadedFiles := []loadedFile{}
	for pid, name := range pidNames {
		stdout := ""
		stdout, err = o.procExe(pid)
		if err != nil {
			// TODO wrap
			return err
		}
		s, err := o.parseProcExe(stdout)
		if err != nil {
			// TODO wrap or only logging
			return err
		}
		loadedFiles = append(loadedFiles, loadedFile{
			pid:      pid,
			procName: name,
			path:     s,
		})

		stdout, err = o.procMap(pid)
		if err != nil {
			// TODO wrap
			return err
		}
		ss := o.parseProcMap(stdout)
		for _, s := range ss {
			loadedFiles = append(loadedFiles, loadedFile{
				pid:      pid,
				procName: name,
				path:     s,
			})
		}
	}

	for i, loaded := range loadedFiles {
		name, ok, err := o.getPkgName(loaded.path)
		if err != nil {
			// TODO wrap
			return err
		}
		if !ok {
			continue
		}
		loaded.pkgName = name
		loadedFiles[i] = loaded
	}

	fmt.Println(loadedFiles)
	return nil
}

// How to install yum-plugin-ps on RHEL7
// # yum-config-manager --enable rhui-REGION-rhel-server-optional
// # yum install yum-plugin-ps
// # yum-config-manager --disable rhui-REGION-rhel-server-optional
func (o *redhatBase) yumPS() error {
	cmd := "LANGUAGE=en_US.UTF-8 yum info yum"
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumPS())
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to SSH: %s", r)
	}
	if !o.checkYumPsInstalled(r.Stdout) {
		switch o.Distro.Family {
		case config.Oracle:
			return nil
		default:
			return xerrors.New("yum-plugin-ps is not installed")
		}
	}

	cmd = "LANGUAGE=en_US.UTF-8 yum -q ps all --color=never"
	r = o.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to SSH: %s", r)
	}
	packs := o.parseYumPS(r.Stdout)
	for name, pack := range packs {
		p := o.Packages[name]
		p.AffectedProcs = pack.AffectedProcs
		o.Packages[name] = p
	}
	return nil
}

func (o *redhatBase) checkYumPsInstalled(stdout string) bool {
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Loaded plugins: ") {
			if strings.Contains(line, " ps,") || strings.HasSuffix(line, " ps") {
				return true
			}
			return false
		}
	}
	return false
}

func (o *redhatBase) parseYumPS(stdout string) models.Packages {
	packs := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	isPackageLine, needToParseProcline := false, false
	currentPackName := ""
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 ||
			len(fields) == 1 && fields[0] == "ps" ||
			len(fields) == 6 && fields[0] == "pid" {
			continue
		}

		isPackageLine = !strings.HasPrefix(line, " ")
		if isPackageLine {
			if 1 < len(fields) && fields[1] == "Upgrade" {
				needToParseProcline = true

				// Search o.Packages to divide into name, version, release
				name, pack, found := o.Packages.FindOne(func(p models.Package) bool {
					var epochNameVerRel string
					if index := strings.Index(p.Version, ":"); 0 < index {
						epoch := p.Version[0:index]
						ver := p.Version[index+1 : len(p.Version)]
						epochNameVerRel = fmt.Sprintf("%s:%s-%s-%s.%s",
							epoch, p.Name, ver, p.Release, p.Arch)
					} else {
						epochNameVerRel = fmt.Sprintf("%s-%s-%s.%s",
							p.Name, p.Version, p.Release, p.Arch)
					}
					return strings.HasPrefix(fields[0], epochNameVerRel)
				})
				if !found {
					o.log.Errorf("`yum ps` package is not found: %s", line)
					continue
				}
				packs[name] = pack
				currentPackName = name
			} else {
				needToParseProcline = false
			}
		} else if needToParseProcline {
			if 6 < len(fields) {
				proc := models.AffectedProcess{
					PID:  fields[0],
					Name: fields[1],
				}
				pack := packs[currentPackName]
				pack.AffectedProcs = append(pack.AffectedProcs, proc)
				packs[currentPackName] = pack
			} else {
				o.log.Errorf("`yum ps` Unknown Format: %s", line)
				continue
			}
		}
	}
	return packs
}

func (o *redhatBase) needsRestarting() error {
	initName, err := o.detectInitSystem()
	if err != nil {
		o.log.Warn(err)
		// continue scanning
	}

	cmd := "LANGUAGE=en_US.UTF-8 needs-restarting"
	r := o.exec(cmd, sudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to SSH: %w", r)
	}
	procs := o.parseNeedsRestarting(r.Stdout)
	for _, proc := range procs {
		fqpn, err := o.procPathToFQPN(proc.Path)
		if err != nil {
			o.log.Warnf("Failed to detect a package name of need restarting process from the command path: %s, %s",
				proc.Path, err)
			continue
		}
		pack, err := o.Packages.FindByFQPN(fqpn)
		if err != nil {
			return err
		}
		if initName == systemd {
			name, err := o.detectServiceName(proc.PID)
			if err != nil {
				o.log.Warn(err)
				// continue scanning
			}
			proc.ServiceName = name
			proc.InitSystem = systemd
		}
		pack.NeedRestartProcs = append(pack.NeedRestartProcs, proc)
		o.Packages[pack.Name] = *pack
	}
	return nil
}

func (o *redhatBase) parseNeedsRestarting(stdout string) (procs []models.NeedRestartProcess) {
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Replace(line, "\x00", " ", -1) // for CentOS6.9
		ss := strings.Split(line, " : ")
		if len(ss) < 2 {
			continue
		}
		// https://unix.stackexchange.com/a/419375
		if ss[0] == "1" {
			continue
		}

		path := ss[1]
		if !strings.HasPrefix(path, "/") {
			path = strings.Fields(path)[0]
			// [ec2-user@ip-172-31-11-139 ~]$ sudo needs-restarting
			// 2024 : auditd
			// [ec2-user@ip-172-31-11-139 ~]$ type -p auditd
			// /sbin/auditd
			cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 which %s", path)
			r := o.exec(cmd, sudo)
			if !r.isSuccess() {
				o.log.Warnf("Failed to exec which %s: %s", path, r)
				continue
			}
			path = strings.TrimSpace(r.Stdout)
		}

		procs = append(procs, models.NeedRestartProcess{
			PID:     ss[0],
			Path:    path,
			HasInit: true,
		})
	}
	return
}

// procPathToFQPN returns Fully-Qualified-Package-Name from the command
func (o *redhatBase) procPathToFQPN(execCommand string) (string, error) {
	execCommand = strings.Replace(execCommand, "\x00", " ", -1) // for CentOS6.9
	path := strings.Fields(execCommand)[0]
	cmd := `LANGUAGE=en_US.UTF-8 rpm -qf --queryformat "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n" ` + path
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	fqpn := strings.TrimSpace(r.Stdout)
	return strings.Replace(fqpn, "-(none):", "-", -1), nil
}

func (o *redhatBase) hasYumColorOption() bool {
	cmd := "yum --help | grep color"
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	return len(r.Stdout) > 0
}

func (o *redhatBase) ps() (stdout string, err error) {
	cmd := `ps  --no-headers --ppid 2 -p 2 --deselect -o pid,comm | awk '{print $1,$2}'`
	// TODO sudo
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumPS())
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (o *redhatBase) parsePs(stdout string) map[string]string {
	pidNames := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		ss := strings.Fields(line)
		if len(ss) < 2 {
			continue
		}
		pidNames[ss[0]] = ss[1]
	}
	return pidNames
}

func (o *redhatBase) procExe(pid string) (stdout string, err error) {
	cmd := fmt.Sprintf("ls -l /proc/%s/exe", pid)
	r := o.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (o *redhatBase) parseProcExe(stdout string) (string, error) {
	ss := strings.Fields(stdout)
	if len(ss) < 11 {
		return "", xerrors.Errorf("Unknown format: %s", stdout)
	}
	return ss[10], nil
}

func (o *redhatBase) procMap(pid string) (stdout string, err error) {
	cmd := fmt.Sprintf(`cat /proc/%s/maps 2>/dev/null | grep -v " 00:00 " | awk '{print $6}' | sort -n | uniq`, pid)
	r := o.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (o *redhatBase) parseProcMap(stdout string) (soPaths []string) {
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		soPaths = append(soPaths, line)
	}
	return soPaths
}

func (o *redhatBase) getPkgName(path string) (pkgName string, found bool, err error) {
	cmd := fmt.Sprintf(`rpm -qf %s`, path)
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess() {
		return "", false, xerrors.Errorf("Failed to SSH: %s", r)
	}
	s := strings.TrimSpace(r.Stdout)
	return s, s != "", nil
}
