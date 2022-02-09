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
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckDeps(o.depsFastRoot())
	} else if o.getServerInfo().Mode.IsDeep() {
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
	} else if o.getServerInfo().Mode.IsFastRoot() {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsFastRoot())
	} else {
		return o.execCheckIfSudoNoPasswd(o.sudoNoPasswdCmdsDeep())
	}
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

func (o *suse) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	o.Kernel.RebootRequired, err = o.rebootRequired()
	if err != nil {
		err = xerrors.Errorf("Failed to detect the kernel reboot required: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	}

	if o.getServerInfo().Mode.IsOffline() {
		o.Packages = installed
		return nil
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

func (o *suse) rebootRequired() (bool, error) {
	r := o.exec("rpm -q --last kernel-default", noSudo)
	if !r.isSuccess() {
		o.log.Warnf("Failed to detect the last installed kernel : %v", r)
		// continue scanning
		return false, nil
	}
	stdout := strings.Fields(r.Stdout)[0]
	return !strings.Contains(stdout, strings.TrimSuffix(o.Kernel.Release, "-default")), nil
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
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "S | Repository") || strings.Contains(line, "--+----------------") || warnRepoPattern.MatchString(line) {
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
