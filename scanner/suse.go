package scanner

import (
	"bufio"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type suse struct {
	redhatBase
}

// newSUSE is constructor
func newSUSE(c config.ServerInfo) *suse {
	r := &suse{
		redhatBase: redhatBase{
			base: base{
				osPackages: osPackages{
					Packages:  models.Packages{},
					VulnInfos: models.VulnInfos{},
				},
			},
		},
	}
	r.log = logging.NewNormalLogger()
	r.setServerInfo(c)
	return r
}

// https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/suse.rb
func detectSUSE(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/os-release", noSudo); r.isSuccess() {
		if r := exec(c, "zypper -V", noSudo); r.isSuccess() {
			if r := exec(c, "cat /etc/os-release", noSudo); r.isSuccess() {
				s := newSUSE(c)
				name, ver := s.parseOSRelease(r.Stdout)
				if name == "" || ver == "" {
					s.setErrs([]error{xerrors.Errorf("Failed to parse /etc/os-release: %s", r.Stdout)})
					return true, s
				}
				s.setDistro(name, ver)
				return true, s
			}
		}
	} else if r := exec(c, "ls /etc/SuSE-release", noSudo); r.isSuccess() {
		if r := exec(c, "zypper -V", noSudo); r.isSuccess() {
			if r := exec(c, "cat /etc/SuSE-release", noSudo); r.isSuccess() {
				s := newSUSE(c)
				re := regexp.MustCompile(`openSUSE (\d+\.\d+|\d+)`)
				result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
				if len(result) == 2 {
					s.setDistro(constant.OpenSUSE, result[1])
					return true, s
				}

				re = regexp.MustCompile(`VERSION = (\d+)`)
				result = re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
				if len(result) == 2 {
					version := result[1]
					re = regexp.MustCompile(`PATCHLEVEL = (\d+)`)
					result = re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
					if len(result) == 2 {
						s.setDistro(constant.SUSEEnterpriseServer, fmt.Sprintf("%s.%s", version, result[1]))
						return true, s
					}
				}
				s.setErrs([]error{xerrors.Errorf("Failed to parse /etc/SuSE-release: %s", r.Stdout)})
				return true, s
			}
		}
	}
	logging.Log.Debugf("Not SUSE Linux. servername: %s", c.ServerName)
	return false, nil
}

func (o *suse) parseOSRelease(content string) (name string, ver string) {
	if strings.Contains(content, `CPE_NAME="cpe:/o:opensuse:opensuse`) {
		name = constant.OpenSUSE
	} else if strings.Contains(content, `CPE_NAME="cpe:/o:opensuse:tumbleweed`) {
		return constant.OpenSUSE, "tumbleweed"
	} else if strings.Contains(content, `CPE_NAME="cpe:/o:opensuse:leap`) {
		name = constant.OpenSUSELeap
	} else if strings.Contains(content, `CPE_NAME="cpe:/o:suse:sles`) {
		name = constant.SUSEEnterpriseServer
	} else if strings.Contains(content, `CPE_NAME="cpe:/o:suse:sled`) {
		name = constant.SUSEEnterpriseDesktop
	} else {
		return "", ""
	}

	re := regexp.MustCompile(`VERSION_ID=\"(.+)\"`)
	result := re.FindStringSubmatch(strings.TrimSpace(content))
	if len(result) != 2 {
		return "", ""
	}
	return name, result[1]
}

func (o *suse) checkScanMode() error {
	return nil
}

func (o *suse) checkDeps() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckDeps(o.depsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	}
	if o.getServerInfo().Mode.IsDeep() {
		return o.execCheckDeps(o.depsDeep())
	}
	return xerrors.New("Unknown scan mode")
}

func (o *suse) depsFast() []string {
	return []string{}
}

func (o *suse) depsFastRoot() []string {
	return []string{}
}

func (o *suse) depsDeep() []string {
	return o.depsFastRoot()
}

func (o *suse) checkIfSudoNoPasswd() error {
	if o.getServerInfo().Mode.IsFast() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFast())
	}
	if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	}
	return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
}

func (o *suse) sudoNoPasswdCmdsFast() []cmd {
	return []cmd{}
}

func (o *suse) sudoNoPasswdCmdsDeep() []cmd {
	return o.sudoNoPasswdCmdsFastRoot()
}

func (o *suse) sudoNoPasswdCmdsFastRoot() []cmd {
	if !o.ServerInfo.IsContainer() {
		return []cmd{
			{"zypper ps -s", exitStatusZero},
			{"which which", exitStatusZero},
			{"stat /proc/1/exe", exitStatusZero},
			{"ls -l /proc/1/exe", exitStatusZero},
			{"cat /proc/1/maps", exitStatusZero},
			{"lsof -i -P -n", exitStatusZero},
		}
	}
	return []cmd{
		{"zypper ps -s", exitStatusZero},
	}
}

func (o *suse) scanPackages() (err error) {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	o.Packages, o.SrcPackages, err = o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	fn := func(pkgNames []string) execResult {
		// LANGUAGE for the message of a package that is not installed
		return o.exec(fmt.Sprintf("LANGUAGE=en_US.UTF-8 rpm -q --last %s", strings.Join(pkgNames, " ")), noSudo)
	}
	o.Kernel.RebootRequired, err = o.rebootRequired(fn)
	if err != nil {
		err = xerrors.Errorf("Failed to detect the kernel reboot required: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	}

	if o.getServerInfo().Mode.IsOffline() {
		return nil
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

var suseKernelFlavorPattern = regexp.MustCompile(`^[0-9A-Za-z_]+$`)

// splitSUSEKernelRelease splits the running kernel release into the release without the flavor and the flavor,
// e.g. 6.12.0-160000.41-default -> 6.12.0-160000.41, default.
// ok is false for a release without a valid flavor, e.g. the kernel of a container host.
func splitSUSEKernelRelease(release string) (running, flavor string, ok bool) {
	i := strings.LastIndex(release, "-")
	if i < 0 || !suseKernelFlavorPattern.MatchString(release[i+1:]) {
		return "", "", false
	}
	return release[:i], release[i+1:], true
}

// suseKernelFlavors are the known flavors of SUSE kernels. kernel-<flavor> runs as <version>-<release>-<flavor>.
var suseKernelFlavors = []string{"64kb", "azure", "debug", "default", "kvmsmall", "longterm", "lpae", "nvidia", "nvidia64kb", "pae", "preempt", "rt", "rt_debug", "vanilla", "xen", "zfcpdump"}

// suseKernelFlavorSubpackages are the subpackages of kernel-<flavor> that can be installed in multiple versions, e.g. kernel-default-devel.
var suseKernelFlavorSubpackages = []string{"base", "devel", "extra", "optional", "livepatch"}

// suseKernelCommonPackages are the kernel packages shared among the flavors that can be installed in multiple versions.
var suseKernelCommonPackages = []string{
	"kernel-devel", "kernel-devel-azure", "kernel-devel-longterm", "kernel-devel-nvidia", "kernel-devel-rt",
	"kernel-source", "kernel-source-azure", "kernel-source-longterm", "kernel-source-nvidia", "kernel-source-rt", "kernel-source-vanilla",
	"kernel-syms", "kernel-syms-azure", "kernel-syms-longterm", "kernel-syms-nvidia", "kernel-syms-rt",
}

// parseSUSEKernelFlavorPackageName parses kernel-<flavor> or kernel-<flavor>-<subpackage> for the given flavors.
func parseSUSEKernelFlavorPackageName(name string, flavors []string) (flavor, subpackage string, ok bool) {
	for _, f := range flavors {
		rest, found := strings.CutPrefix(name, fmt.Sprintf("kernel-%s", f))
		if !found {
			continue
		}
		if rest == "" {
			return f, "", true
		}
		if s, found := strings.CutPrefix(rest, "-"); found && slices.Contains(suseKernelFlavorSubpackages, s) {
			return f, s, true
		}
	}
	return "", "", false
}

// isRunningSUSEKernel reports whether pack is a kernel package that can be installed in multiple versions, and whether it is of the running kernel.
func isRunningSUSEKernel(pack models.Package, kernel models.Kernel) (isKernel, running bool) {
	runningRelease, runningFlavor, ok := splitSUSEKernelRelease(kernel.Release)

	flavor, subpackage := "", ""
	if !slices.Contains(suseKernelCommonPackages, pack.Name) {
		flavors := suseKernelFlavors
		if ok && !slices.Contains(flavors, runningFlavor) {
			// a flavor unknown to vuls is also handled if it is running
			flavors = append(slices.Clone(flavors), runningFlavor)
		}
		var isFlavorPackage bool
		flavor, subpackage, isFlavorPackage = parseSUSEKernelFlavorPackageName(pack.Name, flavors)
		if !isFlavorPackage {
			return false, false
		}
	}

	if !ok || (flavor != "" && flavor != runningFlavor) {
		return true, false
	}

	if subpackage == "base" {
		// kernel-<flavor>-base may append its own release to the release of kernel-<flavor>,
		// e.g. kernel-default-base-6.12.0-160000.41.1.160000.2.33 runs as 6.12.0-160000.41-default, so compare by prefix.
		return true, strings.HasPrefix(fmt.Sprintf("%s-%s", pack.Version, pack.Release), fmt.Sprintf("%s.", runningRelease))
	}
	// The running kernel release omits the build counter, e.g. kernel-default-6.12.0-160000.41.1 runs as 6.12.0-160000.41-default.
	i := strings.LastIndex(pack.Release, ".")
	return true, i >= 0 && fmt.Sprintf("%s-%s", pack.Version, pack.Release[:i]) == runningRelease
}

// rebootRequired reports whether the last installed kernel of the running flavor differs from the running kernel.
// The running kernel can be provided by kernel-<flavor>-base instead of kernel-<flavor> (e.g. openSUSE Leap Minimal VM), so both are queried.
func (o *suse) rebootRequired(fn func(pkgNames []string) execResult) (bool, error) {
	running, flavor, ok := splitSUSEKernelRelease(o.Kernel.Release)
	if !ok {
		// e.g. the kernel of a container host. The flavor is also passed to the shell, so do not use an unexpected one.
		o.log.Debugf("Failed to detect the flavor of the running kernel. release: %q", o.Kernel.Release)
		return false, nil
	}

	pkgNames := []string{fmt.Sprintf("kernel-%s", flavor), fmt.Sprintf("kernel-%s-base", flavor)}
	r := fn(pkgNames)
	// rpm -q exits with the number of packages that are not installed, reporting each of them, e.g. "package kernel-default is not installed".
	// A nonzero exit status without such reports, e.g. a failure of the command itself, is an error.
	notInstalled := 0
	for _, line := range slices.Concat(strings.Split(r.Stdout, "\n"), strings.Split(r.Stderr, "\n")) {
		if fields := strings.Fields(line); len(fields) == 5 && fields[0] == "package" && slices.Contains(pkgNames, fields[1]) && strings.Join(fields[2:], " ") == "is not installed" {
			notInstalled++
		}
	}
	if !r.isSuccess(0, 1, 2) || notInstalled != r.ExitStatus {
		return false, xerrors.Errorf("Failed to detect the last installed kernel : %v", r)
	}

	// $ rpm -q --last kernel-default kernel-default-base
	// kernel-default-base-6.12.0-160000.41.1.160000.2.33.x86_64 Tue Nov 24 09:51:20 2026
	// kernel-default-base-6.12.0-160000.40.1.160000.2.29.x86_64 Tue Nov 24 09:51:07 2026
	// package kernel-default is not installed
	scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "kernel-") {
			continue
		}
		// The running kernel release omits the build counter of kernel-<flavor>, and kernel-<flavor>-base appends its own release to that of kernel-<flavor>.
		// e.g. both kernel-default-6.12.0-160000.41.1 and kernel-default-base-6.12.0-160000.41.1.160000.2.33 run as 6.12.0-160000.41-default
		for _, n := range pkgNames {
			if strings.HasPrefix(fields[0], fmt.Sprintf("%s-%s.", n, running)) {
				return false, nil
			}
		}
		return true, nil
	}
	return false, nil
}

func (o *suse) scanUpdatablePackages() (models.Packages, error) {
	cmd := "zypper -q lu"
	if o.hasZypperColorOption() {
		cmd = "zypper -q --no-color lu"
	}
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to scan updatable packages: %v", r)
	}
	return o.parseZypperLULines(r.Stdout)
}

var warnRepoPattern = regexp.MustCompile(`Warning: Repository '.+' appears to be outdated\. Consider using a different mirror or server\.`)

func (o *suse) parseZypperLULines(stdout string) (models.Packages, error) {
	updatables := models.Packages{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	headerParsed := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || warnRepoPattern.MatchString(line) {
			continue
		}

		if !headerParsed {
			if func() bool {
				for _, c := range line {
					if !strings.ContainsRune("-+", c) {
						return false
					}
				}
				return true
			}() {
				headerParsed = true
			}
			continue
		}

		pack, err := o.parseZypperLUOneLine(line)
		if err != nil {
			return nil, err
		}
		updatables[pack.Name] = *pack
	}
	return updatables, nil
}

func (o *suse) parseZypperLUOneLine(line string) (*models.Package, error) {
	ss := strings.Split(line, "|")
	if len(ss) != 6 {
		return nil, xerrors.Errorf("zypper -q lu Unknown format: %s", line)
	}
	available := strings.Split(strings.TrimSpace(ss[4]), "-")
	if len(available) != 2 {
		return nil, xerrors.Errorf("unexpected Available Version. expected: %q, actual: %q", "<major>-<release>", strings.TrimSpace(ss[4]))
	}
	return &models.Package{
		Name:       strings.TrimSpace(ss[2]),
		NewVersion: available[0],
		NewRelease: available[1],
		Arch:       strings.TrimSpace(ss[5]),
	}, nil
}

func (o *suse) hasZypperColorOption() bool {
	cmd := "zypper --help | grep color"
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	return len(r.Stdout) > 0
}

func (o *suse) postScan() error {
	if o.isExecYumPS() {
		if err := o.pkgPs(o.getOwnerPkgs); err != nil {
			err = xerrors.Errorf("Failed to execute zypper-ps: %w", err)
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

func (o *suse) needsRestarting() error {
	initName, err := o.detectInitSystem()
	if err != nil {
		o.log.Warn(err)
		// continue scanning
	}

	cmd := "LANGUAGE=en_US.UTF-8 zypper ps -s"
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

func (o *suse) parseNeedsRestarting(stdout string) []models.NeedRestartProcess {
	procs := []models.NeedRestartProcess{}

	// PID | PPID | UID | User | Command | Service
	// ----+------+-----+------+---------+-----------
	// 9   | 7    | 0   | root | bash    | containerd
	// 53  | 9    | 0   | root | zypper  | containerd
	// 55  | 53   | 0   | root | lsof    |

	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		ss := strings.Split(line, " | ")
		if len(ss) < 6 {
			continue
		}
		pid := strings.TrimSpace(ss[0])
		if strings.HasPrefix(pid, "PID") {
			continue
		}
		// https://unix.stackexchange.com/a/419375
		if pid == "1" {
			continue
		}

		cmd := strings.TrimSpace(ss[4])
		whichCmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 which %s", cmd)
		r := o.exec(whichCmd, sudo)
		if !r.isSuccess() {
			o.log.Debugf("Failed to exec which %s: %s", cmd, r)
			continue
		}
		path := strings.TrimSpace(r.Stdout)

		procs = append(procs, models.NeedRestartProcess{
			PID:     pid,
			Path:    path,
			HasInit: true,
		})
	}
	return procs
}
