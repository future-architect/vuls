package scanner

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"

	ver "github.com/knqyf263/go-rpm-version"
)

var releasePattern = regexp.MustCompile(`(.*) release (\d[\d\.]*)`)

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		if r := exec(c, "cat /etc/fedora-release", noSudo); r.isSuccess() {
			fed := newFedora(c)
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				fed.setErrs([]error{xerrors.Errorf("Failed to parse /etc/fedora-release. r.Stdout: %s", r.Stdout)})
				return true, fed
			}
			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				fed.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, fed
			}
			if major < 32 {
				fed.setErrs([]error{xerrors.Errorf("Failed to init Fedora. err: not supported major version. versions prior to Fedora 32 are not supported, detected version is %s", release)})
				return true, fed
			}
			fed.setDistro(constant.Fedora, release)
			return true, fed
		}
	}

	if r := exec(c, "ls /etc/oracle-release", noSudo); r.isSuccess() {
		// Need to discover Oracle Linux first, because it provides an
		// /etc/redhat-release that matches the upstream distribution
		if r := exec(c, "cat /etc/oracle-release", noSudo); r.isSuccess() {
			ora := newOracle(c)
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				ora.setErrs([]error{xerrors.Errorf("Failed to parse /etc/oracle-release. r.Stdout: %s", r.Stdout)})
				return true, ora
			}
			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				ora.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, ora
			}
			if major < 5 {
				ora.setErrs([]error{xerrors.Errorf("Failed to init Oracle Linux. err: not supported major version. versions prior to Oracle Linux 5 are not supported, detected version is %s", release)})
				return true, ora
			}
			ora.setDistro(constant.Oracle, release)
			return true, ora
		}
	}

	if r := exec(c, "ls /etc/almalinux-release", noSudo); r.isSuccess() {
		if r := exec(c, "cat /etc/almalinux-release", noSudo); r.isSuccess() {
			alma := newAlma(c)
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				alma.setErrs([]error{xerrors.Errorf("Failed to parse /etc/almalinux-release. r.Stdout: %s", r.Stdout)})
				return true, alma
			}

			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				alma.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, alma
			}
			if major < 8 {
				alma.setErrs([]error{xerrors.Errorf("Failed to init AlmaLinux. err: not supported major version. versions prior to AlmaLinux 8 are not supported, detected version is %s", release)})
				return true, alma
			}
			switch strings.ToLower(result[1]) {
			case "alma", "almalinux":
				alma.setDistro(constant.Alma, release)
				return true, alma
			default:
				alma.setErrs([]error{xerrors.Errorf("Failed to parse AlmaLinux Name. release: %s", release)})
				return true, alma
			}
		}
	}

	if r := exec(c, "ls /etc/rocky-release", noSudo); r.isSuccess() {
		if r := exec(c, "cat /etc/rocky-release", noSudo); r.isSuccess() {
			rocky := newRocky(c)
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				rocky.setErrs([]error{xerrors.Errorf("Failed to parse /etc/rocky-release. r.Stdout: %s", r.Stdout)})
				return true, rocky
			}

			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				rocky.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, rocky
			}
			if major < 8 {
				rocky.setErrs([]error{xerrors.Errorf("Failed to init Rocky Linux. err: not supported major version. versions prior to Rocky Linux 8 are not supported, detected version is %s", release)})
				return true, rocky
			}
			switch strings.ToLower(result[1]) {
			case "rocky", "rocky linux":
				rocky.setDistro(constant.Rocky, release)
				return true, rocky
			default:
				rocky.setErrs([]error{xerrors.Errorf("Failed to parse Rocky Linux Name. release: %s", release)})
				return true, rocky
			}
		}
	}

	// https://bugzilla.redhat.com/show_bug.cgi?id=1332025
	// CentOS cloud image
	if r := exec(c, "ls /etc/centos-release", noSudo); r.isSuccess() {
		if r := exec(c, "cat /etc/centos-release", noSudo); r.isSuccess() {
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				cent := newCentOS(c)
				cent.setErrs([]error{xerrors.Errorf("Failed to parse /etc/centos-release. r.Stdout: %s", r.Stdout)})
				return true, cent
			}

			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				cent := newCentOS(c)
				cent.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, cent
			}
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				cent := newCentOS(c)
				if major < 5 {
					cent.setErrs([]error{xerrors.Errorf("Failed to init CentOS. err: not supported major version. versions prior to CentOS 5 are not supported, detected version is %s", release)})
					return true, cent
				}
				cent.setDistro(constant.CentOS, release)
				return true, cent
			case "centos stream":
				cent := newCentOS(c)
				if major < 8 {
					cent.setErrs([]error{xerrors.Errorf("Failed to init CentOS Stream. err: not supported major version. versions prior to CentOS Stream 8 are not supported, detected version is %s", release)})
					return true, cent
				}
				cent.setDistro(constant.CentOS, fmt.Sprintf("stream%s", release))
				return true, cent
			case "alma", "almalinux":
				alma := newAlma(c)
				if major < 8 {
					alma.setErrs([]error{xerrors.Errorf("Failed to init AlmaLinux. err: not supported major version. versions prior to AlmaLinux 8 are not supported, detected version is %s", release)})
					return true, alma
				}
				alma.setDistro(constant.Alma, release)
				return true, alma
			case "rocky", "rocky linux":
				rocky := newRocky(c)
				if major < 8 {
					rocky.setErrs([]error{xerrors.Errorf("Failed to init Rocky Linux. err: not supported major version. versions prior to Rocky Linux 8 are not supported, detected version is %s", release)})
					return true, rocky
				}
				rocky.setDistro(constant.Rocky, release)
				return true, rocky
			default:
				cent := newCentOS(c)
				cent.setErrs([]error{xerrors.Errorf("Failed to parse CentOS Name. release: %s", release)})
				return true, cent
			}
		}
	}

	if r := exec(c, "ls /etc/amazon-linux-release", noSudo); r.isSuccess() {
		// $ cat /etc/amazon-linux-release
		// Amazon Linux release 2022 (Amazon Linux)
		// Amazon Linux release 2023 (Amazon Linux)
		// Amazon Linux release 2023.3.20240312 (Amazon Linux)
		if r := exec(c, "cat /etc/amazon-linux-release", noSudo); r.isSuccess() {
			amazon := newAmazon(c)
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				amazon.setErrs([]error{xerrors.Errorf("Failed to parse /etc/amazon-linux-release. r.Stdout: %s", r.Stdout)})
				return true, amazon
			}

			release := result[2]
			major, err := strconv.Atoi(util.Major(release))
			if err != nil {
				amazon.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
				return true, amazon
			}
			if major < 2022 {
				amazon.setErrs([]error{xerrors.Errorf("Failed to init Amazon Linux. err: not supported major version. versions prior to Amazon Linux 2022 are not supported, detected version is %s", release)})
				return true, amazon
			}
			switch strings.ToLower(result[1]) {
			case "amazon", "amazon linux":
				amazon.setDistro(constant.Amazon, release)
				return true, amazon
			default:
				amazon.setErrs([]error{xerrors.Errorf("Failed to parse Amazon Linux Name. release: %s", release)})
				return true, amazon
			}
		}
	}

	if r := exec(c, "ls /etc/redhat-release", noSudo); r.isSuccess() {
		// https://www.rackaid.com/blog/how-to-determine-centos-or-red-hat-version/
		// e.g.
		// $ cat /etc/redhat-release
		// Red Hat Enterprise Linux Server release 6.8 (Santiago)
		// CentOS release 6.5 (Final)
		// CentOS Stream release 8
		// AlmaLinux release 8.5 (Arctic Sphynx)
		// Rocky Linux release 8.5 (Green Obsidian)
		// Fedora release 35 (Thirty Five)
		if r := exec(c, "cat /etc/redhat-release", noSudo); r.isSuccess() {
			result := releasePattern.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) == 3 {
				release := result[2]
				major, err := strconv.Atoi(util.Major(release))
				if err != nil {
					rhel := newRHEL(c)
					rhel.setErrs([]error{xerrors.Errorf("Failed to parse major version from release: %s", release)})
					return true, rhel
				}
				switch strings.ToLower(result[1]) {
				case "fedora":
					fed := newFedora(c)
					if major < 32 {
						fed.setErrs([]error{xerrors.Errorf("Failed to init Fedora. err: not supported major version. versions prior to Fedora 32 are not supported, detected version is %s", release)})
						return true, fed
					}
					fed.setDistro(constant.Fedora, release)
					return true, fed
				case "centos", "centos linux":
					cent := newCentOS(c)
					if major < 5 {
						cent.setErrs([]error{xerrors.Errorf("Failed to init CentOS. err: not supported major version. versions prior to CentOS 5 are not supported, detected version is %s", release)})
						return true, cent
					}
					cent.setDistro(constant.CentOS, release)
					return true, cent
				case "centos stream":
					cent := newCentOS(c)
					if major < 8 {
						cent.setErrs([]error{xerrors.Errorf("Failed to init CentOS Stream. err: not supported major version. versions prior to CentOS Stream 8 are not supported, detected version is %s", release)})
						return true, cent
					}
					cent.setDistro(constant.CentOS, fmt.Sprintf("stream%s", release))
					return true, cent
				case "alma", "almalinux":
					alma := newAlma(c)
					if major < 8 {
						alma.setErrs([]error{xerrors.Errorf("Failed to init AlmaLinux. err: not supported major version. versions prior to AlmaLinux 8 are not supported, detected version is %s", release)})
						return true, alma
					}
					alma.setDistro(constant.Alma, release)
					return true, alma
				case "rocky", "rocky linux":
					rocky := newRocky(c)
					if major < 8 {
						rocky.setErrs([]error{xerrors.Errorf("Failed to init Rocky Linux. err: not supported major version. versions prior to Rocky Linux 8 are not supported, detected version is %s", release)})
						return true, rocky
					}
					rocky.setDistro(constant.Rocky, release)
					return true, rocky
				default:
					rhel := newRHEL(c)
					if major < 5 {
						rhel.setErrs([]error{xerrors.Errorf("Failed to init RedHat Enterprise Linux. err: not supported major version. versions prior to RedHat Enterprise Linux 5 are not supported, detected version is %s", release)})
						return true, rhel
					}
					rhel.setDistro(constant.RedHat, release)
					return true, rhel
				}
			}
		}
	}

	if r := exec(c, "ls /etc/system-release", noSudo); r.isSuccess() {
		family := constant.Amazon
		release := "unknown"
		if r := exec(c, "cat /etc/system-release", noSudo); r.isSuccess() {
			switch {
			case strings.HasPrefix(r.Stdout, "Amazon Linux AMI release"):
				// Amazon Linux AMI release 2017.09
				// Amazon Linux AMI release 2018.03
				release = "1"
			case strings.HasPrefix(r.Stdout, "Amazon Linux 2022"), strings.HasPrefix(r.Stdout, "Amazon Linux release 2022"):
				// Amazon Linux 2022 (Amazon Linux)
				// Amazon Linux release 2022 (Amazon Linux)
				release = "2022"
			case strings.HasPrefix(r.Stdout, "Amazon Linux 2023"), strings.HasPrefix(r.Stdout, "Amazon Linux release 2023"):
				// Amazon Linux 2023 (Amazon Linux)
				// Amazon Linux release 2023 (Amazon Linux)
				// Amazon Linux release 2023.3.20240312 (Amazon Linux)
				release = "2023"
			case strings.HasPrefix(r.Stdout, "Amazon Linux 2"), strings.HasPrefix(r.Stdout, "Amazon Linux release 2"):
				// Amazon Linux 2 (Karoo)
				// Amazon Linux release 2 (Karoo)
				release = "2"
			default:
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
			o.log.Errorf("%s is not installed", name)
			return xerrors.Errorf("%s is not installed", name)
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
	o.Packages, o.SrcPackages, err = o.scanInstalledPackages()
	if err != nil {
		return xerrors.Errorf("Failed to scan installed packages: %w", err)
	}

	fn := func(pkgName string) execResult { return o.exec(fmt.Sprintf("rpm -q --last %s", pkgName), noSudo) }
	o.Kernel.RebootRequired, err = o.rebootRequired(fn)
	if err != nil {
		err = xerrors.Errorf("Failed to detect the kernel reboot required: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	}

	if o.getServerInfo().Mode.IsOffline() || (o.Distro.Family == constant.RedHat && o.getServerInfo().Mode.IsFast()) {
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

func (o *redhatBase) scanInstalledPackages() (models.Packages, models.SrcPackages, error) {
	release, version, err := o.runningKernel()
	if err != nil {
		return nil, nil, err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	var r execResult
	switch o.getDistro().Family {
	case constant.Amazon:
		switch strings.Fields(o.getDistro().Release)[0] {
		case "2":
			if o.exec("rpm -q yum-utils", noSudo).isSuccess() {
				r = o.exec("repoquery --all --pkgnarrow=installed --qf='%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM} %{UI_FROM_REPO}'", o.sudo.repoquery())
			} else {
				r = o.exec(o.rpmQa(), noSudo)
			}
		default:
			r = o.exec(o.rpmQa(), noSudo)
		}
	default:
		r = o.exec(o.rpmQa(), noSudo)
	}
	if !r.isSuccess() {
		return nil, nil, xerrors.Errorf("Scan packages failed: %s", r)
	}
	bins, srcs, err := o.parseInstalledPackages(r.Stdout)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to parse installed packages. err: %w", err)
	}
	return bins, srcs, nil
}

func (o *redhatBase) parseInstalledPackages(stdout string) (models.Packages, models.SrcPackages, error) {
	bins := make(models.Packages)
	srcs := make(models.SrcPackages)
	latestKernelRelease := ver.NewVersion("")

	// openssl 0 1.0.1e	30.el6.11 x86_64
	// community-mysql-common 0 8.0.26 1.module_f35+12627+b26747dd x86_64 mysql:8.0:3520210817160118:f27b74a8
	lines := strings.SplitSeq(stdout, "\n")
	for line := range lines {
		if trimmed := strings.TrimSpace(line); trimmed == "" {
			continue
		}

		var (
			binpkg *models.Package
			srcpkg *models.SrcPackage
			err    error
		)
		switch o.getDistro().Family {
		case constant.Amazon:
			switch strings.Fields(o.getDistro().Release)[0] {
			case "2":
				switch len(strings.Split(line, " ")) {
				case 6:
					binpkg, srcpkg, err = o.parseInstalledPackagesLine(line)
				case 7:
					binpkg, srcpkg, err = o.parseInstalledPackagesLineFromRepoquery(line)
				default:
					return nil, nil, xerrors.Errorf("Failed to parse package line: %s", line)
				}
			default:
				binpkg, srcpkg, err = o.parseInstalledPackagesLine(line)
			}
		default:
			binpkg, srcpkg, err = o.parseInstalledPackagesLine(line)
		}
		if err != nil {
			return nil, nil, err
		}

		// `Kernel` and `kernel-devel` package may be installed multiple versions.
		// From the viewpoint of vulnerability detection,
		// pay attention only to the running kernel
		isKernel, running := isRunningKernel(*binpkg, o.Distro.Family, o.Distro.Release, o.Kernel)
		if isKernel {
			if o.Kernel.Release == "" {
				// When the running kernel release is unknown,
				// use the latest release among the installed release
				kernelRelease := ver.NewVersion(fmt.Sprintf("%s-%s", binpkg.Version, binpkg.Release))
				if kernelRelease.LessThan(latestKernelRelease) {
					continue
				}
				latestKernelRelease = kernelRelease
			} else if !running {
				o.log.Debugf("Not a running kernel. pack: %#v, kernel: %#v", binpkg, o.Kernel)
				continue
			} else {
				o.log.Debugf("Found a running kernel. pack: %#v, kernel: %#v", binpkg, o.Kernel)
			}
		}
		bins[binpkg.Name] = *binpkg
		if srcpkg != nil {
			if p, ok := srcs[srcpkg.Name]; ok {
				for _, bn := range p.BinaryNames {
					srcpkg.AddBinaryName(bn)
				}
			}
			srcs[srcpkg.Name] = *srcpkg
		}
	}
	return bins, srcs, nil
}

func (o *redhatBase) parseInstalledPackagesLine(line string) (*models.Package, *models.SrcPackage, error) {
	switch fields := strings.Split(line, " "); len(fields) {
	case 6, 7:
		sp, err := func() (*models.SrcPackage, error) {
			switch fields[5] {
			case "(none)":
				return nil, nil
			default:
				n, v, r, _, _, err := splitFileName(fields[5])
				if err != nil {
					o.warns = append(o.warns, xerrors.Errorf("Failed to parse source rpm file. err: %w", err))
					return nil, nil
				}
				return &models.SrcPackage{
					Name: n,
					Version: func() string {
						switch fields[1] {
						case "0", "(none)":
							if r == "" {
								return v
							}
							return fmt.Sprintf("%s-%s", v, r)
						default:
							if r == "" {
								return fmt.Sprintf("%s:%s", fields[1], v)
							}
							return fmt.Sprintf("%s:%s-%s", fields[1], v, r)
						}
					}(),
					Arch:        "src",
					BinaryNames: []string{fields[0]},
				}, nil
			}
		}()
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse sourcepkg. err: %w", err)
		}

		return &models.Package{
			Name: fields[0],
			Version: func() string {
				switch fields[1] {
				case "0", "(none)":
					return fields[2]
				default:
					return fmt.Sprintf("%s:%s", fields[1], fields[2])
				}
			}(),
			Release: fields[3],
			Arch:    fields[4],
			ModularityLabel: func() string {
				if len(fields) == 7 && fields[6] != "(none)" {
					return fields[6]
				}
				return ""
			}(),
		}, sp, nil
	default:
		return nil, nil, xerrors.Errorf("Failed to parse package line: %s", line)
	}
}

func (o *redhatBase) parseInstalledPackagesLineFromRepoquery(line string) (*models.Package, *models.SrcPackage, error) {
	switch fields := strings.Split(line, " "); len(fields) {
	case 7:
		sp, err := func() (*models.SrcPackage, error) {
			switch fields[5] {
			case "(none)":
				return nil, nil
			default:
				n, v, r, _, _, err := splitFileName(fields[5])
				if err != nil {
					o.warns = append(o.warns, xerrors.Errorf("Failed to parse source rpm file. err: %w", err))
					return nil, nil
				}
				return &models.SrcPackage{
					Name: n,
					Version: func() string {
						switch fields[1] {
						case "0", "(none)":
							if r == "" {
								return v
							}
							return fmt.Sprintf("%s-%s", v, r)
						default:
							if r == "" {
								return fmt.Sprintf("%s:%s", fields[1], v)
							}
							return fmt.Sprintf("%s:%s-%s", fields[1], v, r)
						}
					}(),
					Arch:        "src",
					BinaryNames: []string{fields[0]},
				}, nil
			}
		}()
		if err != nil {
			return nil, nil, xerrors.Errorf("Failed to parse sourcepkg. err: %w", err)
		}

		return &models.Package{
			Name: fields[0],
			Version: func() string {
				switch fields[1] {
				case "0", "(none)":
					return fields[2]
				default:
					return fmt.Sprintf("%s:%s", fields[1], fields[2])
				}
			}(),
			Release: fields[3],
			Arch:    fields[4],
			Repository: func() string {
				switch repo := strings.TrimPrefix(fields[6], "@"); repo {
				case "installed":
					return "amzn2-core"
				default:
					return repo
				}
			}(),
		}, sp, nil
	default:
		return nil, nil, xerrors.Errorf("Failed to parse package line: %s", line)
	}
}

// splitFileName returns a name, version, release, epoch, arch:
//
//	e.g.
//		foo-1.0-1.i386.rpm => foo, 1.0, 1, i386
//		1:bar-9-123a.ia64.rpm => bar, 9, 123a, 1, ia64
//
// https://github.com/rpm-software-management/yum/blob/043e869b08126c1b24e392f809c9f6871344c60d/rpmUtils/miscutils.py#L301
func splitFileName(filename string) (name, ver, rel, epoch, arch string, err error) {
	basename := strings.TrimSuffix(filename, ".rpm")

	archIndex := strings.LastIndex(basename, ".")
	// support not standard style rpm fullname
	// e.g.
	//   baz-0-1-i386 => i386
	//   qux-0--i386 => i386
	if i := strings.LastIndex(basename[archIndex+1:], "-"); i > -1 {
		archIndex = archIndex + (i + 1)
	}
	if archIndex == -1 {
		return "", "", "", "", "", xerrors.Errorf("unexpected file name. expected: %q, actual: %q", "(<epoch>:)<name>-<version>-(<release>)(.|-)<arch>.rpm", filename)
	}
	arch = basename[archIndex+1:]

	relIndex := strings.LastIndex(basename[:archIndex], "-")
	if relIndex == -1 {
		return "", "", "", "", "", xerrors.Errorf("unexpected file name. expected: %q, actual: %q", "(<epoch>:)<name>-<version>-(<release>)(.|-)<arch>.rpm", filename)
	}
	rel = basename[relIndex+1 : archIndex]

	verIndex := strings.LastIndex(basename[:relIndex], "-")
	if verIndex == -1 {
		return "", "", "", "", "", xerrors.Errorf("unexpected file name. expected: %q, actual: %q", "(<epoch>:)<name>-<version>-(<release>)(.|-)<arch>.rpm", filename)
	}
	ver = basename[verIndex+1 : relIndex]

	epochIndex := strings.Index(basename, ":")
	if epochIndex != -1 {
		epoch = basename[:epochIndex]
	}

	name = basename[epochIndex+1 : verIndex]
	return name, ver, rel, epoch, arch, nil
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
	pkg, _, err = o.parseInstalledPackagesLine(line)
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
	cmd := `repoquery --all --pkgnarrow=updates --qf='"%{NAME}" "%{EPOCH}" "%{VERSION}" "%{RELEASE}" "%{REPO}"'`
	switch o.getDistro().Family {
	case constant.Fedora:
		v, _ := o.getDistro().MajorVersion()
		switch {
		case v < 41:
			if o.exec(util.PrependProxyEnv(`repoquery --version | grep dnf`), o.sudo.repoquery()).isSuccess() {
				cmd = `repoquery --upgrades --qf='"%{NAME}" "%{EPOCH}" "%{VERSION}" "%{RELEASE}" "%{REPONAME}"' -q`
			}
		default:
			cmd = `repoquery --upgrades --qf='"%{NAME}" "%{EPOCH}" "%{VERSION}" "%{RELEASE}" "%{REPONAME}"' -q`
		}
	default:
		if o.exec(util.PrependProxyEnv(`repoquery --version | grep dnf`), o.sudo.repoquery()).isSuccess() {
			cmd = `repoquery --upgrades --qf='"%{NAME}" "%{EPOCH}" "%{VERSION}" "%{RELEASE}" "%{REPONAME}"' -q`
		}
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
	for line := range strings.SplitSeq(stdout, "\n") {
		pack, err := o.parseUpdatablePacksLine(line)
		if err != nil {
			return updatable, err
		}
		if pack != nil {
			updatable[pack.Name] = *pack
		}
	}
	return updatable, nil
}

func (o *redhatBase) parseUpdatablePacksLine(line string) (*models.Package, error) {
	if strings.HasPrefix(line, "Loading") {
		return nil, nil
	}

	_, rhs, ok := strings.Cut(line, "[y/N]: ")
	if ok {
		line = rhs
	}

	if strings.TrimSpace(line) == "" {
		return nil, nil
	}

	switch fields := strings.Split(line, "\" \""); len(fields) {
	case 5:
		if !strings.HasPrefix(fields[0], "\"") {
			return nil, xerrors.Errorf("unexpected format. expected: %q, actual: %q", "\"<name>\" \"<epoch>\" \"<version>\" \"<release>\" \"<repository>\"", line)
		}
		return &models.Package{
			Name: strings.TrimPrefix(fields[0], "\""),
			NewVersion: func() string {
				if fields[1] == "0" {
					return fields[2]
				}
				return fmt.Sprintf("%s:%s", fields[1], fields[2])
			}(),
			NewRelease: fields[3],
			Repository: strings.TrimSuffix(fields[4], "\""),
		}, nil
	default:
		return nil, xerrors.Errorf("unexpected format. expected: %q, actual: %q", "\"<name>\" \"<epoch>\" \"<version>\" \"<release>\" \"<repository>\"", line)
	}
}

func (o *redhatBase) isExecYumPS() bool {
	switch o.Distro.Family {
	case constant.Oracle:
		return false
	}
	return !o.getServerInfo().Mode.IsFast()
}

func (o *redhatBase) isExecNeedsRestarting() bool {
	switch o.Distro.Family {
	case constant.OpenSUSE, constant.OpenSUSELeap, constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		if o.getServerInfo().Mode.IsOffline() {
			return false
		} else if o.getServerInfo().Mode.IsFastRoot() || o.getServerInfo().Mode.IsDeep() {
			return true
		}
		return false
	case constant.RedHat, constant.CentOS, constant.Alma, constant.Rocky, constant.Oracle:
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil || majorVersion < 6 {
			o.log.Errorf("Not implemented yet: %s, err: %+v", o.Distro, err)
			return false
		}

		if o.getServerInfo().Mode.IsOffline() {
			return false
		} else if o.getServerInfo().Mode.IsFastRoot() || o.getServerInfo().Mode.IsDeep() {
			return true
		}
		return false
	case constant.Fedora:
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil || majorVersion < 13 {
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

	return !o.getServerInfo().Mode.IsFast()
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
		line = strings.ReplaceAll(line, "\x00", " ") // for CentOS6.9
		ss := strings.Split(line, " : ")
		if len(ss) < 2 {
			continue
		}
		// https://unix.stackexchange.com/a/419375
		if ss[0] == "1" {
			continue
		}

		pid := ss[0]
		path := ss[1]
		if path != "" && !strings.HasPrefix(path, "/") {
			// Path is not absolute, use /proc/<PID>/exe to get the actual executable path
			// This handles cases like "sshd: vagrant [priv]", "(sd-pam)", "-bash"
			cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 readlink -f /proc/%s/exe", pid)
			r := o.exec(cmd, sudo)
			if r.isSuccess() {
				path = strings.TrimSpace(r.Stdout)
			} else {
				// Fallback to old behavior (using which)
				path = strings.Fields(path)[0]
				cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 which %s", path)
				r := o.exec(cmd, sudo)
				if !r.isSuccess() {
					o.log.Debugf("Failed to exec which %s: %s", path, r)
					continue
				}
				path = strings.TrimSpace(r.Stdout)
			}
		}

		// Resolve symlinks to get the real path before rpm -qf
		// This handles cases like /usr/sbin/VBoxService -> /opt/VBoxGuestAdditions-*/sbin/VBoxService
		cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 readlink -f %s", path)
		r := o.exec(cmd, sudo)
		if r.isSuccess() {
			resolvedPath := strings.TrimSpace(r.Stdout)
			if resolvedPath != "" {
				path = resolvedPath
			}
		}

		procs = append(procs, models.NeedRestartProcess{
			PID:     pid,
			Path:    path,
			HasInit: true,
		})
	}
	return
}

// TODO refactor
// procPathToFQPN returns Fully-Qualified-Package-Name from the command
func (o *redhatBase) procPathToFQPN(execCommand string) (string, error) {
	execCommand = strings.ReplaceAll(execCommand, "\x00", " ") // for CentOS6.9
	originalPath := strings.Fields(execCommand)[0]

	// First try with the original path
	cmd := fmt.Sprintf("%s %s", o.rpmQf(), originalPath)
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	pack, ignored, err := o.parseRpmQfLine(r.Stdout)
	if err != nil {
		return "", xerrors.Errorf("Failed to parse rpm -qf line: %s, err: %+v", r.Stdout, err)
	}
	if !ignored {
		return pack.FQPN(), nil
	}

	// If original path didn't work, try resolving symlinks
	// This handles cases like /usr/sbin/arptables -> /etc/alternatives/arptables
	cmd = fmt.Sprintf("LANGUAGE=en_US.UTF-8 readlink -f %s", originalPath)
	r = o.exec(util.PrependProxyEnv(cmd), noSudo)
	if r.isSuccess() {
		resolvedPath := strings.TrimSpace(r.Stdout)
		if resolvedPath != "" && resolvedPath != originalPath {
			cmd = fmt.Sprintf("%s %s", o.rpmQf(), resolvedPath)
			r = o.exec(util.PrependProxyEnv(cmd), noSudo)
			if r.isSuccess() {
				pack, ignored, err = o.parseRpmQfLine(r.Stdout)
				if err != nil {
					return "", xerrors.Errorf("Failed to parse rpm -qf line: %s, err: %+v", r.Stdout, err)
				}
				if !ignored {
					return pack.FQPN(), nil
				}
			}
		}
	}

	return "", xerrors.Errorf("Failed to return FQPN. line: %s, err: ignore line", r.Stdout)
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
	const old = `rpm -qa --queryformat "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n"`
	const newer = `rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n"`
	const modularity = `rpm -qa --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM} %{MODULARITYLABEL}\n"`
	switch o.Distro.Family {
	case constant.OpenSUSE:
		if o.Distro.Release == "tumbleweed" {
			return newer
		}
		return old
	case constant.OpenSUSELeap:
		return newer
	case constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		if v, _ := o.Distro.MajorVersion(); v < 12 {
			return old
		}
		return newer
	case constant.Fedora:
		if v, _ := o.Distro.MajorVersion(); v < 30 {
			return newer
		}
		return modularity
	case constant.Amazon:
		switch v, _ := o.Distro.MajorVersion(); v {
		case 1, 2:
			return newer
		default:
			return modularity
		}
	default:
		v, _ := o.Distro.MajorVersion()
		if v < 6 {
			return old
		}
		if v >= 8 {
			return modularity
		}
		return newer
	}
}

func (o *redhatBase) rpmQf() string {
	const old = `rpm -qf --queryformat "%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n" `
	const newer = `rpm -qf --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM}\n"`
	const modularity = `rpm -qf --queryformat "%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE} %{ARCH} %{SOURCERPM} %{MODULARITYLABEL}\n"`
	switch o.Distro.Family {
	case constant.OpenSUSE:
		if o.Distro.Release == "tumbleweed" {
			return newer
		}
		return old
	case constant.OpenSUSELeap:
		return newer
	case constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		if v, _ := o.Distro.MajorVersion(); v < 12 {
			return old
		}
		return newer
	case constant.Fedora:
		if v, _ := o.Distro.MajorVersion(); v < 30 {
			return newer
		}
		return modularity
	case constant.Amazon:
		switch v, _ := o.Distro.MajorVersion(); v {
		case 1, 2:
			return newer
		default:
			return modularity
		}
	default:
		v, _ := o.Distro.MajorVersion()
		if v < 6 {
			return old
		}
		if v >= 8 {
			return modularity
		}
		return newer
	}
}
