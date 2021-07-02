package scanner

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"

	ver "github.com/knqyf263/go-rpm-version"
)

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		logging.Log.Warnf("Fedora not tested yet: %s", r)
		return true, &unknown{}
	}

	if r := exec(c, "ls /etc/oracle-release", noSudo); r.isSuccess() {
		// Need to discover Oracle Linux first, because it provides an
		// /etc/redhat-release that matches the upstream distribution
		if r := exec(c, "cat /etc/oracle-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				logging.Log.Warnf("Failed to parse Oracle Linux version: %s", r)
				return true, newOracle(c)
			}

			ora := newOracle(c)
			release := result[2]
			ora.setDistro(constant.Oracle, release)
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
				logging.Log.Warnf("Failed to parse CentOS version: %s", r)
				return true, newCentOS(c)
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux", "centos stream":
				cent := newCentOS(c)
				cent.setDistro(constant.CentOS, release)
				return true, cent
			default:
				logging.Log.Warnf("Failed to parse CentOS: %s", r)
			}
		}
	}

	if r := exec(c, "ls /etc/rocky-release", noSudo); r.isSuccess() {
		if r := exec(c, "cat /etc/rocky-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				logging.Log.Warnf("Failed to parse Rocky version: %s", r)
				return true, newRocky(c)
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "rocky", "rocky linux":
				rocky := newRocky(c)
				rocky.setDistro(constant.Rocky, release)
				return true, rocky
			default:
				logging.Log.Warnf("Failed to parse Rocky: %s", r)
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
				logging.Log.Warnf("Failed to parse RedHat/CentOS version: %s", r)
				return true, newCentOS(c)
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux", "centos stream":
				cent := newCentOS(c)
				cent.setDistro(constant.CentOS, release)
				return true, cent
			case "rocky", "rocky linux":
				rocky := newRocky(c)
				rocky.setDistro(constant.Rocky, release)
				return true, rocky
			default:
				// RHEL
				rhel := newRHEL(c)
				rhel.setDistro(constant.RedHat, release)
				return true, rhel
			}
		}
	}

	if r := exec(c, "ls /etc/system-release", noSudo); r.isSuccess() {
		family := constant.Amazon
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

	logging.Log.Debugf("Not RedHat like Linux. servername: %s", c.ServerName)
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
	if o.isExecYumPS() {
		if err := o.pkgPs(o.getOwnerPkgs); err != nil {
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
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

func (o *redhatBase) scanPackages() (err error) {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	o.Packages, err = o.scanInstalledPackages()
	if err != nil {
		return xerrors.Errorf("Failed to scan installed packages: %w", err)
	}

	if o.EnabledDnfModules, err = o.detectEnabledDnfModules(); err != nil {
		return xerrors.Errorf("Failed to detect installed dnf modules: %w", err)
	}

	fn := func(pkgName string) execResult { return o.exec(fmt.Sprintf("rpm -q --last %s", pkgName), noSudo) }
	o.Kernel.RebootRequired, err = o.rebootRequired(fn)
	if err != nil {
		err = xerrors.Errorf("Failed to detect the kernel reboot required: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	}

	if o.getServerInfo().Mode.IsOffline() {
		return nil
	} else if o.Distro.Family == constant.RedHat {
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
		o.Packages.MergeNewVersion(updatable)
	}
	return nil
}

func (o *redhatBase) rebootRequired(fn func(s string) execResult) (bool, error) {
	pkgName := "kernel"
	if strings.Contains(o.Kernel.Release, "uek.") {
		pkgName = "kernel-uek"
	}

	r := fn(pkgName)
	scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
	if !r.isSuccess(0, 1) {
		return false, xerrors.Errorf("Failed to detect the last installed kernel : %v", r)
	}
	if !r.isSuccess() || !scanner.Scan() {
		return false, nil
	}
	lastInstalledKernelVer := strings.Fields(scanner.Text())[0]
	running := fmt.Sprintf("%s-%s", pkgName, o.Kernel.Release)
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

	r := o.exec(o.rpmQa(), noSudo)
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
		if trimmed := strings.TrimSpace(line); trimmed == "" {
			continue
		}
		pack, err := o.parseInstalledPackagesLine(line)
		if err != nil {
			return nil, nil, err
		}

		// `Kernel` and `kernel-devel` package may be installed multiple versions.
		// From the viewpoint of vulnerability detection,
		// pay attention only to the running kernel
		isKernel, running := isRunningKernel(*pack, o.Distro.Family, o.Kernel)
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
		installed[pack.Name] = *pack
	}
	return installed, nil, nil
}

func (o *redhatBase) parseInstalledPackagesLine(line string) (*models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return nil,
			xerrors.Errorf("Failed to parse package line: %s", line)
	}

	ver := ""
	epoch := fields[1]
	if epoch == "0" || epoch == "(none)" {
		ver = fields[2]
	} else {
		ver = fmt.Sprintf("%s:%s", epoch, fields[2])
	}

	return &models.Package{
		Name:    fields[0],
		Version: ver,
		Release: fields[3],
		Arch:    fields[4],
	}, nil
}

func (o *redhatBase) parseRpmQfLine(line string) (pkg *models.Package, ignored bool, err error) {
	for _, suffix := range []string{
		"Permission denied",
		"is not owned by any package",
		"No such file or directory",
	} {
		if strings.HasSuffix(line, suffix) {
			return nil, true, nil
		}
	}
	pkg, err = o.parseInstalledPackagesLine(line)
	return pkg, false, err
}

func (o *redhatBase) yumMakeCache() error {
	cmd := `yum makecache --assumeyes`
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumMakeCache())
	if !r.isSuccess(0, 1) {
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

	// Collect Updatable packages, installed, candidate version and repository.
	return o.parseUpdatablePacksLines(r.Stdout)
}

// parseUpdatablePacksLines parse the stdout of repoquery to get package name, candidate version
func (o *redhatBase) parseUpdatablePacksLines(stdout string) (models.Packages, error) {
	updatable := models.Packages{}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
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
	case constant.Oracle,
		constant.OpenSUSE,
		constant.OpenSUSELeap,
		constant.SUSEEnterpriseServer,
		constant.SUSEEnterpriseDesktop,
		constant.SUSEOpenstackCloud:
		return false
	}
	return !o.getServerInfo().Mode.IsFast()
}

func (o *redhatBase) isExecNeedsRestarting() bool {
	switch o.Distro.Family {
	case constant.OpenSUSE,
		constant.OpenSUSELeap,
		constant.SUSEEnterpriseServer,
		constant.SUSEEnterpriseDesktop,
		constant.SUSEOpenstackCloud:
		// TODO zypper ps
		// https://github.com/future-architect/vuls/issues/696
		return false
	case constant.RedHat, constant.CentOS, constant.Rocky, constant.Oracle:
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil || majorVersion < 6 {
			o.log.Errorf("Not implemented yet: %s, err: %+v", o.Distro, err)
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
		//TODO refactor
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
				o.log.Debugf("Failed to exec which %s: %s", path, r)
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

//TODO refactor
// procPathToFQPN returns Fully-Qualified-Package-Name from the command
func (o *redhatBase) procPathToFQPN(execCommand string) (string, error) {
	execCommand = strings.Replace(execCommand, "\x00", " ", -1) // for CentOS6.9
	path := strings.Fields(execCommand)[0]
	cmd := `LANGUAGE=en_US.UTF-8 rpm -qf --queryformat "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}\n" ` + path
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	fqpn := strings.TrimSpace(r.Stdout)
	return strings.Replace(fqpn, "-(none):", "-", -1), nil
}

func (o *redhatBase) getOwnerPkgs(paths []string) (names []string, _ error) {
	cmd := o.rpmQf() + strings.Join(paths, " ")
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	// rpm exit code means `the number` of errors.
	// https://listman.redhat.com/archives/rpm-list/2005-July/msg00071.html
	// If we treat non-zero exit codes of `rpm` as errors,
	// we will be missing a partial package list we can get.

	scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
	for scanner.Scan() {
		line := scanner.Text()
		pack, ignored, err := o.parseRpmQfLine(line)
		if ignored {
			continue
		}
		if err != nil {
			o.log.Debugf("Failed to parse rpm -qf line: %s, err: %+v", line, err)
			continue
		}
		if _, ok := o.Packages[pack.Name]; !ok {
			o.log.Debugf("Failed to rpm -qf. pkg: %+v not found, line: %s", pack, line)
			continue
		}
		names = append(names, pack.Name)
	}
	return
}

func (o *redhatBase) rpmQa() string {
	const old = `rpm -qa --queryformat "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH}\n"`
	const new = `rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH}\n"`
	switch o.Distro.Family {
	case constant.SUSEEnterpriseServer:
		if v, _ := o.Distro.MajorVersion(); v < 12 {
			return old
		}
		return new
	default:
		if v, _ := o.Distro.MajorVersion(); v < 6 {
			return old
		}
		return new
	}
}

func (o *redhatBase) rpmQf() string {
	const old = `rpm -qf --queryformat "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH}\n" `
	const new = `rpm -qf --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH}\n" `
	switch o.Distro.Family {
	case constant.SUSEEnterpriseServer:
		if v, _ := o.Distro.MajorVersion(); v < 12 {
			return old
		}
		return new
	default:
		if v, _ := o.Distro.MajorVersion(); v < 6 {
			return old
		}
		return new
	}
}

func (o *redhatBase) detectEnabledDnfModules() ([]string, error) {
	switch o.Distro.Family {
	case constant.RedHat, constant.CentOS, constant.Rocky:
		//TODO OracleLinux
	default:
		return nil, nil
	}
	if v, _ := o.Distro.MajorVersion(); v < 8 {
		return nil, nil
	}

	cmd := `dnf --nogpgcheck --cacheonly --color=never --quiet module list --enabled`
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess() {
		if strings.Contains(r.Stdout, "Cache-only enabled but no cache") {
			return nil, xerrors.Errorf("sudo yum check-update to make local cache before scanning: %s", r)
		}
		return nil, xerrors.Errorf("Failed to dnf module list: %s", r)
	}
	return o.parseDnfModuleList(r.Stdout)
}

func (o *redhatBase) parseDnfModuleList(stdout string) (labels []string, err error) {
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Hint:") || !strings.Contains(line, "[i]") {
			continue
		}
		ss := strings.Fields(line)
		if len(ss) < 2 {
			continue
		}
		labels = append(labels, fmt.Sprintf("%s:%s", ss[0], ss[1]))
	}
	return
}
