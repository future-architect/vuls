/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

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
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"

	ver "github.com/knqyf263/go-rpm-version"
)

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (bool, osTypeInterface) {
	if r := exec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		util.Log.Warn("Fedora not tested yet: %s", r)
		return true, &unknown{}
	}

	if r := exec(c, "ls /etc/oracle-release", noSudo); r.isSuccess() {
		// Need to discover Oracle Linux first, because it provides an
		// /etc/redhat-release that matches the upstream distribution
		if r := exec(c, "cat /etc/oracle-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				util.Log.Warn("Failed to parse Oracle Linux version: %s", r)
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
				util.Log.Warn("Failed to parse CentOS version: %s", r)
				return true, newCentOS(c)
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				cent := newCentOS(c)
				cent.setDistro(config.CentOS, release)
				return true, cent
			default:
				util.Log.Warn("Failed to parse CentOS: %s", r)
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
				util.Log.Warn("Failed to parse RedHat/CentOS version: %s", r)
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
	yumRepolist() bool
	yumUpdateInfo() bool
	yumChangelog() bool
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
			return fmt.Errorf("Failed to sudo: %s", r)
		}
	}
	o.log.Infof("Sudo... Pass")
	return nil
}

//TODO move to each concrete struct
func (o *redhatBase) _checkIfSudoNoPasswd() error {
	if !(config.Conf.Deep || config.Conf.FastRoot) {
		o.log.Infof("sudo ... No need")
		return nil
	}

	type cmd struct {
		cmd                 string
		expectedStatusCodes []int
	}
	var cmds []cmd
	var zero = []int{0}

	switch o.Distro.Family {
	case config.RedHat, config.Oracle:
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil {
			return fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
		}

		if majorVersion < 6 {
			cmds = []cmd{
				{"yum --color=never repolist", zero},
				{"yum --color=never list-security --security", zero},
				{"yum --color=never info-security", zero},
			}
		} else {
			cmds = []cmd{
				{"yum --color=never repolist", zero},
				{"yum --color=never --security updateinfo list updates", zero},
				{"yum --color=never --security updateinfo updates", zero},
				//TODO only CentOS , amazon?, oracle?
				{"yum --color=never -q ps all", zero},
			}
		}
		if o.Distro.Family == config.RedHat {
			cmds = append(cmds, cmd{"repoquery -h", zero})
		}

	case config.CentOS, config.Amazon:
		cmds = []cmd{
			{"yum --color=never -q ps all", zero},
		}
	}

	for _, c := range cmds {
		cmd := util.PrependProxyEnv(c.cmd)
		o.log.Infof("Checking... sudo %s", cmd)
		// r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
		// if !r.isSuccess(c.expectedStatusCodes...) {
		// o.log.Errorf("Check sudo or proxy settings: %s", r)
		// return fmt.Errorf("Failed to sudo: %s", r)
		// }
	}
	o.log.Infof("Sudo... Pass")
	return nil
}

// https://docs.google.com/spreadsheets/d/1F0QjkafI7ouz5fCV2-wbqzOXQgYuCPuBR9A2d9zdVKk/edit?usp=sharing
//TODO fix doc: add yum info yum to sudoers on RHEL7
//TODO remove
func (o *redhatBase) _checkDeps() error {
	majorVersion, err := o.Distro.MajorVersion()
	if err != nil {
		msg := fmt.Sprintf("Not implemented yet: %s, err: %s", o.Distro, err)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	if o.Distro.Family == config.CentOS {
		if majorVersion < 6 {
			msg := fmt.Sprintf("CentOS %s is not supported any more", o.Distro.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}

	packNames := []string{}
	switch {
	case config.Conf.Fast:
		// Fast Scan
		if !config.Conf.Offline {
			// Online fast scan needs yum-utils to issue repoquery cmd
			packNames = append(packNames, "yum-utils")
		}

	case config.Conf.FastRoot:
		// Fast-Root Scan
		switch o.Distro.Family {
		case config.Amazon:
			// Offline scan doesn't support Amazon Linux
			packNames = append(packNames,
				"yum-utils",
				"yum-plugin-ps")

		default:
			if config.Conf.Offline {
				if o.Distro.Family == config.CentOS {
					// TODO Check Oracle linux
					packNames = append(packNames, "yum-plugin-ps")
				}
			} else {
				switch o.Distro.Family {
				case config.CentOS:
					packNames = append(packNames,
						"yum-utils",
						"yum-plugin-ps")
				case config.RedHat, config.Oracle:
					switch majorVersion {
					case 5:
						packNames = append(packNames,
							"yum-utils",
							"yum-security")
					case 6:
						packNames = append(packNames,
							"yum-utils",
							"yum-plugin-security")
					default:
						packNames = append(packNames, "yum-utils")
					}
				}
			}
		}

	default:
		// Deep Scan
		switch o.Distro.Family {
		case config.CentOS, config.Amazon:
			packNames = append(packNames,
				"yum-utils",
				"yum-plugin-changelog",
				//TODO check whether Amazon linux has yum-plugin-ps
				"yum-plugin-ps")
		case config.RedHat, config.Oracle:
			switch majorVersion {
			case 5:
				packNames = append(packNames,
					"yum-utils",
					"yum-security",
					"yum-changelog",
				)
			case 6:
				packNames = append(packNames,
					"yum-utils",
					"yum-plugin-security",
					"yum-plugin-changelog",
				)
			default:
				packNames = append(packNames,
					"yum-utils",
					"yum-plugin-changelog",
				)
			}
		default:
			return fmt.Errorf("Not implemented yet: %s", o.Distro)
		}
	}

	// for _, name := range packNames {
	// cmd := "rpm -q " + name
	// if r := o.exec(cmd, noSudo); !r.isSuccess() {
	// msg := fmt.Sprintf("%s is not installed", name)
	// o.log.Errorf(msg)
	// return fmt.Errorf(msg)
	// }
	// }
	o.log.Infof("Dependencies ... Pass")
	return nil
}

func (o *redhatBase) execCheckDeps(packNames []string) error {
	for _, name := range packNames {
		cmd := "rpm -q " + name
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("%s is not installed", name)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}
	o.log.Infof("Dependencies ... Pass")
	return nil
}

func (o *redhatBase) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Debugf("Failed to detect IP addresses: %s", err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *redhatBase) postScan() error {
	if o.isExecYumPS() {
		if err := o.yumPS(); err != nil {
			return fmt.Errorf("Failed to execute yum-ps: %s", err)
		}
	}
	if o.isExecNeedsRestarting() {
		if err := o.needsRestarting(); err != nil {
			return fmt.Errorf("Failed to execute need-restarting: %s", err)
		}
	}
	return nil
}

func (o *redhatBase) detectIPAddr() (err error) {
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs, err = o.ip()
	return err
}

func (o *redhatBase) scanPackages() error {
	installed, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}

	rebootRequired, err := o.rebootRequired()
	if err != nil {
		o.log.Errorf("Failed to detect the kernel reboot required: %s", err)
		return err
	}
	o.Kernel.RebootRequired = rebootRequired

	if config.Conf.Offline {
		switch o.Distro.Family {
		case config.Amazon:
			// nop
		default:
			o.Packages = installed
			return nil
		}
	} else if o.Distro.Family == config.RedHat {
		if config.Conf.Fast {
			o.Packages = installed
			return nil
		}
	}

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	installed.MergeNewVersion(updatable)
	o.Packages = installed

	var unsecures models.VulnInfos
	if unsecures, err = o.scanUnsecurePackages(updatable); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages: %s", err)
		return err
	}
	o.VulnInfos = unsecures
	return nil
}

func (o *redhatBase) rebootRequired() (bool, error) {
	r := o.exec("rpm -q --last kernel", noSudo)
	scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
	if !r.isSuccess(0, 1) {
		return false, fmt.Errorf("Failed to detect the last installed kernel : %v", r)
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

	installed := models.Packages{}
	r := o.exec(rpmQa(o.Distro), noSudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Scan packages failed: %s", r)
	}

	// openssl 0 1.0.1e	30.el6.11 x86_64
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		if trimed := strings.TrimSpace(line); len(trimed) != 0 {
			pack, err := o.parseInstalledPackagesLine(line)
			if err != nil {
				return nil, err
			}

			// Kernel package may be isntalled multiple versions.
			// From the viewpoint of vulnerability detection,
			// pay attention only to the running kernel
			isKernel, running := isRunningKernel(pack, o.Distro.Family, o.Kernel)
			if isKernel {
				if !running {
					o.log.Debugf("Not a running kernel. pack: %#v, kernel: %#v", pack, o.Kernel)
					continue
				}
				o.log.Debugf("Found a running kernel. pack: %#v, kernel: %#v", pack, o.Kernel)
			}
			installed[pack.Name] = pack
		}
	}
	return installed, nil
}

func (o *redhatBase) parseInstalledPackagesLine(line string) (models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return models.Package{},
			fmt.Errorf("Failed to parse package line: %s", line)
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

func (o *redhatBase) scanUpdatablePackages() (models.Packages, error) {
	cmd := `repoquery --all --pkgnarrow=updates --qf="%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{REPO}"`
	for _, repo := range o.getServerInfo().Enablerepo {
		cmd += " --enablerepo=" + repo
	}

	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.repoquery())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
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
		return models.Package{}, fmt.Errorf("Unknown format: %s, fields: %s", line, fields)
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

func (o *redhatBase) isExecScanUsingYum() bool {
	if config.Conf.Offline {
		return false
	}
	if o.Distro.Family == config.CentOS {
		// CentOS doesn't have security channel
		return false
	}
	if config.Conf.FastRoot || config.Conf.Deep {
		return true
	}
	return false
}

func (o *redhatBase) isExecFillChangelogs() bool {
	if config.Conf.Offline {
		return false
	}
	// Amazon linux has no changelos for updates
	return config.Conf.Deep &&
		o.Distro.Family != config.Amazon
}

func (o *redhatBase) isExecScanChangelogs() bool {
	if config.Conf.Offline || config.Conf.Fast || config.Conf.FastRoot {
		return false
	}
	return true
}

func (o *redhatBase) isExecYumPS() bool {
	// RedHat has no yum-ps
	if o.Distro.Family == config.RedHat {
		return false
	}
	// yum ps needs internet connection
	if config.Conf.Offline || config.Conf.Fast {
		return false
	}
	return true
}

func (o *redhatBase) isExecNeedsRestarting() bool {
	if o.Distro.Family == config.RedHat {
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil || majorVersion < 6 {
			o.log.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
			return false
		}

		if config.Conf.Offline {
			return false
		} else if config.Conf.FastRoot || config.Conf.Deep {
			return true
		}
		return false
	}

	if config.Conf.Fast {
		return false
	}
	return true
}

func (o *redhatBase) scanUnsecurePackages(updatable models.Packages) (models.VulnInfos, error) {
	if o.isExecFillChangelogs() {
		if err := o.fillChangelogs(updatable); err != nil {
			return nil, err
		}
	}

	if o.isExecScanUsingYum() {
		return o.scanUsingYum(updatable)
	}

	// Parse chnagelog because CentOS does not have security channel...
	if o.isExecScanChangelogs() {
		return o.scanChangelogs(updatable)
	}

	return models.VulnInfos{}, nil
}

func (o *redhatBase) fillChangelogs(updatables models.Packages) error {
	names := []string{}
	for name := range updatables {
		names = append(names, name)
	}

	if err := o.fillDiffChangelogs(names); err != nil {
		return err
	}

	emptyChangelogPackNames := []string{}
	for _, pack := range o.Packages {
		if pack.NewVersion != "" && pack.Changelog.Contents == "" {
			emptyChangelogPackNames = append(emptyChangelogPackNames, pack.Name)
		}
	}

	i := 0
	for _, name := range emptyChangelogPackNames {
		i++
		o.log.Infof("(%d/%d) Fetched Changelogs %s", i, len(emptyChangelogPackNames), name)
		if err := o.fillDiffChangelogs([]string{name}); err != nil {
			return err
		}
	}

	return nil
}

func (o *redhatBase) getAvailableChangelogs(packNames []string) (map[string]string, error) {
	yumopts := ""
	if 0 < len(o.getServerInfo().Enablerepo) {
		yumopts = " --enablerepo=" + strings.Join(o.getServerInfo().Enablerepo, ",")
	}
	if config.Conf.SkipBroken {
		yumopts += " --skip-broken"
	}
	if o.hasYumColorOption() {
		yumopts += " --color=never"
	}
	cmd := `yum changelog all updates %s %s | grep -A 1000000 "==================== Updated Packages ===================="`
	cmd = fmt.Sprintf(cmd, yumopts, strings.Join(packNames, " "))

	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumChangelog())
	if !r.isSuccess(0, 1) {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	return o.divideChangelogsIntoEachPackages(r.Stdout), nil
}

// Divide available change logs of all updatable packages into each package's changelog
func (o *redhatBase) divideChangelogsIntoEachPackages(stdout string) map[string]string {
	changelogs := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(stdout))

	crlf, newBlock := false, true
	packNameVer, contents := "", []string{}
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "==================== Updated Packages ====================") {
			continue
		}
		if len(strings.TrimSpace(line)) != 0 && newBlock {
			left := strings.Fields(line)[0]
			// ss := strings.Split(left, ".")
			// packNameVer = strings.Join(ss[0:len(ss)-1], ".")
			packNameVer = left
			newBlock = false
			continue
		}
		if len(strings.TrimSpace(line)) == 0 {
			if crlf {
				changelogs[packNameVer] = strings.Join(contents, "\n")
				packNameVer = ""
				contents = []string{}
				newBlock = true
				crlf = false
			} else {
				contents = append(contents, line)
				crlf = true
			}
		} else {
			contents = append(contents, line)
			crlf = false
		}
	}
	if 0 < len(contents) {
		changelogs[packNameVer] = strings.Join(contents, "\n")
	}
	return changelogs
}

func (o *redhatBase) fillDiffChangelogs(packNames []string) error {
	changelogs, err := o.getAvailableChangelogs(packNames)
	if err != nil {
		return err
	}

	for s := range changelogs {
		// name, pack, found := o.Packages.FindOne(func(p models.Package) bool {
		name, pack, found := o.Packages.FindOne(func(p models.Package) bool {
			var epochNameVerRel string
			if index := strings.Index(p.NewVersion, ":"); 0 < index {
				epoch := p.NewVersion[0:index]
				ver := p.NewVersion[index+1 : len(p.NewVersion)]
				epochNameVerRel = fmt.Sprintf("%s:%s-%s", epoch, p.Name, ver)
			} else {
				epochNameVerRel = fmt.Sprintf("%s-%s", p.Name, p.NewVersion)
			}
			return strings.HasPrefix(s, epochNameVerRel)
		})

		if found {
			var detectionMethod string
			diff, err := o.getDiffChangelog(pack, changelogs[s])
			if err == nil {
				detectionMethod = models.ChangelogExactMatchStr
			} else {
				o.log.Debug(err)
				// Try without epoch
				if index := strings.Index(pack.Version, ":"); 0 < index {
					pack.Version = pack.Version[index+1 : len(pack.Version)]
					o.log.Debug("Try without epoch", pack)
					diff, err = o.getDiffChangelog(pack, changelogs[s])
					if err != nil {
						o.log.Debugf("Failed to find the version in changelog: %s-%s-%s",
							pack.Name, pack.Version, pack.Release)
						if len(diff) == 0 {
							detectionMethod = models.FailedToGetChangelog
						} else {
							detectionMethod = models.FailedToFindVersionInChangelog
							diff = ""
						}
					} else {
						o.log.Debugf("Found the version in changelog without epoch: %s-%s-%s",
							pack.Name, pack.Version, pack.Release)
						detectionMethod = models.ChangelogLenientMatchStr
					}
				} else {
					if len(diff) == 0 {
						detectionMethod = models.FailedToGetChangelog
					} else {
						detectionMethod = models.FailedToFindVersionInChangelog
						diff = ""
					}
				}
			}

			pack = o.Packages[name]
			pack.Changelog = models.Changelog{
				Contents: diff,
				Method:   models.DetectionMethod(detectionMethod),
			}
			o.Packages[name] = pack
		}
	}
	return nil
}

func (o *redhatBase) getDiffChangelog(pack models.Package, availableChangelog string) (string, error) {
	installedVer := ver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
	scanner := bufio.NewScanner(strings.NewReader(availableChangelog))
	diff := []string{}
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "* ") {
			diff = append(diff, line)
			continue
		}

		// openssh on RHEL
		//   openssh-server-6.6.1p1-35.el7_3.x86_64   rhui-rhel-7-server-rhui-rpms
		//   Wed Mar  1 21:00:00 2017 Jakub Jelen <jjelen@redhat.com> - 6.6.1p1-35 + 0.9.3-9
		ss := strings.Split(line, " + ")
		if 1 < len(ss) {
			line = ss[0]
		}

		ss = strings.Split(line, " ")
		if len(ss) < 2 {
			diff = append(diff, line)
			continue
		}
		v := ss[len(ss)-1]
		v = strings.TrimPrefix(v, "-")
		v = strings.TrimPrefix(v, "[")
		v = strings.TrimSuffix(v, "]")

		// On Amazon often end with email address. <aaa@aaa.com> Go to next line
		if strings.HasPrefix(v, "<") && strings.HasSuffix(v, ">") {
			diff = append(diff, line)
			continue
		}

		version := ver.NewVersion(v)
		if installedVer.Equal(version) || installedVer.GreaterThan(version) {
			found = true
			break
		}
		diff = append(diff, line)
	}

	if len(diff) == 0 || !found {
		return availableChangelog,
			fmt.Errorf("Failed to find the version in changelog: %s-%s-%s",
				pack.Name, pack.Version, pack.Release)
	}
	return strings.TrimSpace(strings.Join(diff, "\n")), nil
}

func (o *redhatBase) scanChangelogs(updatable models.Packages) (models.VulnInfos, error) {
	packCveIDs := make(map[string][]string)
	for name := range updatable {
		cveIDs := []string{}
		pack := o.Packages[name]
		if pack.Changelog.Method == models.FailedToFindVersionInChangelog {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(pack.Changelog.Contents))
		for scanner.Scan() {
			if matches := cveRe.FindAllString(scanner.Text(), -1); 0 < len(matches) {
				for _, m := range matches {
					cveIDs = util.AppendIfMissing(cveIDs, m)
				}
			}
		}
		packCveIDs[name] = cveIDs
	}

	// transform datastructure
	// - From
	//	  "packname": []{"CVE-2017-1111", ".../
	//
	// - To
	//	   map {
	//		 "CVE-2017-1111": "packname",
	//	   }
	vinfos := models.VulnInfos{}
	for name, cveIDs := range packCveIDs {
		for _, cid := range cveIDs {
			if v, ok := vinfos[cid]; ok {
				v.AffectedPackages = append(v.AffectedPackages, models.PackageStatus{Name: name})
				vinfos[cid] = v
			} else {
				vinfos[cid] = models.VulnInfo{
					CveID:            cid,
					AffectedPackages: models.PackageStatuses{{Name: name}},
					Confidences:      models.Confidences{models.ChangelogExactMatch},
				}
			}
		}
	}
	return vinfos, nil
}

type distroAdvisoryCveIDs struct {
	DistroAdvisory models.DistroAdvisory
	CveIDs         []string
}

// Scaning unsecure packages using yum-plugin-security.
// Amazon, RHEL, Oracle Linux
func (o *redhatBase) scanUsingYum(updatable models.Packages) (models.VulnInfos, error) {
	if o.Distro.Family == config.CentOS {
		// CentOS has no security channel.
		return nil, fmt.Errorf(
			"yum updateinfo is not suppported on CentOS")
	}

	// get advisoryID(RHSA, ALAS, ELSA) - package name,version
	major, err := (o.Distro.MajorVersion())
	if err != nil {
		return nil, fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
	}

	var cmd string
	if (o.Distro.Family == config.RedHat || o.Distro.Family == config.Oracle) && major > 5 {
		cmd = "yum repolist --color=never"
		r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumRepolist())
		if !r.isSuccess() {
			return nil, fmt.Errorf("Failed to SSH: %s", r)
		}
	}

	if (o.Distro.Family == config.RedHat || o.Distro.Family == config.Oracle) && major == 5 {
		cmd = "yum list-security --security"
		if o.hasYumColorOption() {
			cmd += " --color=never"
		}
	} else {
		cmd = "yum updateinfo list updates --security --color=never"
	}
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo.yumUpdateInfo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	advIDPackNamesList, err := o.parseYumUpdateinfoListAvailable(r.Stdout)

	dict := make(map[string]models.Packages)
	for _, advIDPackNames := range advIDPackNamesList {
		packages := models.Packages{}
		for _, packName := range advIDPackNames.PackNames {
			pack, found := updatable[packName]
			if !found {
				return nil, fmt.Errorf(
					"Package not found. pack: %#v", packName)
			}
			packages[pack.Name] = pack
			continue
		}
		dict[advIDPackNames.AdvisoryID] = packages
	}

	// get advisoryID(RHSA, ALAS, ELSA) - CVE IDs
	if (o.Distro.Family == config.RedHat || o.Distro.Family == config.Oracle) && major == 5 {
		cmd = "yum info-security"
		if o.hasYumColorOption() {
			cmd += " --color=never"
		}
	} else {
		cmd = "yum updateinfo updates --security --color=never"
	}
	r = o.exec(util.PrependProxyEnv(cmd), o.sudo.yumUpdateInfo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	advisoryCveIDsList, err := o.parseYumUpdateinfo(r.Stdout)
	if err != nil {
		return nil, err
	}

	// All information collected.
	// Convert to VulnInfos.
	vinfos := models.VulnInfos{}
	for _, advIDCveIDs := range advisoryCveIDsList {
		for _, cveID := range advIDCveIDs.CveIDs {
			vinfo, found := vinfos[cveID]
			if found {
				advAppended := append(vinfo.DistroAdvisories, advIDCveIDs.DistroAdvisory)
				vinfo.DistroAdvisories = advAppended

				packs := dict[advIDCveIDs.DistroAdvisory.AdvisoryID]
				for _, pack := range packs {
					vinfo.AffectedPackages = append(vinfo.AffectedPackages,
						models.PackageStatus{Name: pack.Name})
				}
			} else {
				packs := dict[advIDCveIDs.DistroAdvisory.AdvisoryID]
				affected := models.PackageStatuses{}
				for _, p := range packs {
					affected = append(affected, models.PackageStatus{Name: p.Name})
				}
				vinfo = models.VulnInfo{
					CveID:            cveID,
					DistroAdvisories: []models.DistroAdvisory{advIDCveIDs.DistroAdvisory},
					AffectedPackages: affected,
					Confidences:      models.Confidences{models.YumUpdateSecurityMatch},
				}
			}
			vinfos[cveID] = vinfo
		}
	}
	return vinfos, nil
}

var horizontalRulePattern = regexp.MustCompile(`^=+$`)

func (o *redhatBase) parseYumUpdateinfo(stdout string) (result []distroAdvisoryCveIDs, err error) {
	sectionState := Outside
	lines := strings.Split(stdout, "\n")
	lines = append(lines, "=============")

	// Amazon Linux AMI Security Information
	advisory := models.DistroAdvisory{}

	cveIDsSetInThisSection := make(map[string]bool)

	// use this flag to Collect CVE IDs in CVEs field.
	inDesctiption, inCves := false, false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// find the new section pattern
		if horizontalRulePattern.MatchString(line) {
			// set previous section's result to return-variable
			if sectionState == Content {
				foundCveIDs := []string{}
				for cveID := range cveIDsSetInThisSection {
					foundCveIDs = append(foundCveIDs, cveID)
				}
				result = append(result, distroAdvisoryCveIDs{
					DistroAdvisory: advisory,
					CveIDs:         foundCveIDs,
				})

				// reset for next section.
				cveIDsSetInThisSection = make(map[string]bool)
				inDesctiption, inCves = false, false
				advisory = models.DistroAdvisory{}
			}

			// Go to next section
			sectionState = o.changeSectionState(sectionState)
			continue
		}

		switch sectionState {
		case Header:
			switch o.Distro.Family {
			case config.CentOS:
				// CentOS has no security channel.
				return result, fmt.Errorf(
					"yum updateinfo is not suppported on CentOS")
			case config.RedHat, config.Amazon, config.Oracle:
				// nop
			}

		case Content:
			if found := o.isDescriptionLine(line); found {
				inDesctiption, inCves = true, false
				ss := strings.Split(line, " : ")
				advisory.Description += fmt.Sprintf("%s\n",
					strings.Join(ss[1:], " : "))
				continue
			}

			// severity
			if severity, found := o.parseYumUpdateinfoToGetSeverity(line); found {
				advisory.Severity = severity
				continue
			}

			// No need to parse in description except severity
			if inDesctiption {
				if ss := strings.Split(line, ": "); 1 < len(ss) {
					advisory.Description += fmt.Sprintf("%s\n",
						strings.Join(ss[1:], ": "))
				}
				continue
			}

			if found := o.isCvesHeaderLine(line); found {
				inCves = true
				ss := strings.Split(line, "CVEs : ")
				line = strings.Join(ss[1:], " ")
				cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
				for _, cveID := range cveIDs {
					cveIDsSetInThisSection[cveID] = true
				}
				continue
			}

			if inCves {
				cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
				for _, cveID := range cveIDs {
					cveIDsSetInThisSection[cveID] = true
				}
			}

			advisoryID, found := o.parseYumUpdateinfoToGetAdvisoryID(line)
			if found {
				advisory.AdvisoryID = advisoryID
				continue
			}

			issued, found := o.parseYumUpdateinfoLineToGetIssued(line)
			if found {
				advisory.Issued = issued
				continue
			}

			updated, found := o.parseYumUpdateinfoLineToGetUpdated(line)
			if found {
				advisory.Updated = updated
				continue
			}
		}
	}
	return
}

// state
const (
	Outside = iota
	Header  = iota
	Content = iota
)

func (o *redhatBase) changeSectionState(state int) (newState int) {
	switch state {
	case Outside, Content:
		newState = Header
	case Header:
		newState = Content
	}
	return newState
}

func (o *redhatBase) isCvesHeaderLine(line string) bool {
	return strings.Contains(line, "CVEs : ")
}

var yumCveIDPattern = regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)

func (o *redhatBase) parseYumUpdateinfoLineToGetCveIDs(line string) []string {
	return yumCveIDPattern.FindAllString(line, -1)
}

var yumAdvisoryIDPattern = regexp.MustCompile(`^ *Update ID : (.*)$`)

func (o *redhatBase) parseYumUpdateinfoToGetAdvisoryID(line string) (advisoryID string, found bool) {
	result := yumAdvisoryIDPattern.FindStringSubmatch(line)
	if len(result) != 2 {
		return "", false
	}
	return strings.TrimSpace(result[1]), true
}

var yumIssuedPattern = regexp.MustCompile(`^\s*Issued : (\d{4}-\d{2}-\d{2})`)

func (o *redhatBase) parseYumUpdateinfoLineToGetIssued(line string) (date time.Time, found bool) {
	return o.parseYumUpdateinfoLineToGetDate(line, yumIssuedPattern)
}

var yumUpdatedPattern = regexp.MustCompile(`^\s*Updated : (\d{4}-\d{2}-\d{2})`)

func (o *redhatBase) parseYumUpdateinfoLineToGetUpdated(line string) (date time.Time, found bool) {
	return o.parseYumUpdateinfoLineToGetDate(line, yumUpdatedPattern)
}

func (o *redhatBase) parseYumUpdateinfoLineToGetDate(line string, regexpPattern *regexp.Regexp) (date time.Time, found bool) {
	result := regexpPattern.FindStringSubmatch(line)
	if len(result) != 2 {
		return date, false
	}
	t, err := time.Parse("2006-01-02", result[1])
	if err != nil {
		return date, false
	}
	return t, true
}

var yumDescriptionPattern = regexp.MustCompile(`^\s*Description : `)

func (o *redhatBase) isDescriptionLine(line string) bool {
	return yumDescriptionPattern.MatchString(line)
}

var yumSeverityPattern = regexp.MustCompile(`^ *Severity : (.*)$`)

func (o *redhatBase) parseYumUpdateinfoToGetSeverity(line string) (severity string, found bool) {
	result := yumSeverityPattern.FindStringSubmatch(line)
	if len(result) != 2 {
		return "", false
	}
	return strings.TrimSpace(result[1]), true
}

type advisoryIDPacks struct {
	AdvisoryID string
	PackNames  []string
}

type advisoryIDPacksList []advisoryIDPacks

func (list advisoryIDPacksList) find(advisoryID string) (advisoryIDPacks, bool) {
	for _, a := range list {
		if a.AdvisoryID == advisoryID {
			return a, true
		}
	}
	return advisoryIDPacks{}, false
}
func (o *redhatBase) extractPackNameVerRel(nameVerRel string) (name, ver, rel string) {
	fields := strings.Split(nameVerRel, ".")
	archTrimed := strings.Join(fields[0:len(fields)-1], ".")

	fields = strings.Split(archTrimed, "-")
	rel = fields[len(fields)-1]
	ver = fields[len(fields)-2]
	name = strings.Join(fields[0:(len(fields)-2)], "-")
	return
}

// parseYumUpdateinfoListAvailable collect AdvisorID(RHSA, ALAS, ELSA), packages
func (o *redhatBase) parseYumUpdateinfoListAvailable(stdout string) (advisoryIDPacksList, error) {
	result := []advisoryIDPacks{}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {

		if !(strings.HasPrefix(line, "RHSA") ||
			strings.HasPrefix(line, "ALAS") ||
			strings.HasPrefix(line, "ELSA")) {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			return []advisoryIDPacks{}, fmt.Errorf(
				"Unknown format. line: %s", line)
		}

		// extract fields
		advisoryID := fields[0]
		packVersion := fields[2]
		packName, _, _ := o.extractPackNameVerRel(packVersion)

		found := false
		for i, s := range result {
			if s.AdvisoryID == advisoryID {
				names := s.PackNames
				names = append(names, packName)
				result[i].PackNames = names
				found = true
				break
			}
		}
		if !found {
			result = append(result, advisoryIDPacks{
				AdvisoryID: advisoryID,
				PackNames:  []string{packName},
			})
		}
	}
	return result, nil
}

func (o *redhatBase) yumPS() error {
	cmd := "LANGUAGE=en_US.UTF-8 yum info yum"
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess() {
		return fmt.Errorf("Failed to SSH: %s", r)
	}
	if !o.checkYumPsInstalled(r.Stdout) {
		switch o.Distro.Family {
		case config.RedHat, config.Oracle:
			return nil
		default:
			return fmt.Errorf("yum-plugin-ps is not installed")
		}
	}

	cmd = "LANGUAGE=en_US.UTF-8 yum -q ps all --color=never"
	r = o.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return fmt.Errorf("Failed to SSH: %s", r)
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
		line := scanner.Text()
		if strings.HasPrefix(line, "Loaded plugins: ") {
			if strings.Contains(line, "ps,") {
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
		return fmt.Errorf("Failed to SSH: %s", r)
	}
	procs := o.parseNeedsRestarting(r.Stdout)
	for _, proc := range procs {
		fqpn, err := o.procPathToFQPN(proc.Path)
		if err != nil {
			return err
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
				o.log.Warnf("Failed to exec type -p %s: %s", path, r)
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
	path := strings.Fields(execCommand)[0]
	cmd := `LANGUAGE=en_US.UTF-8 rpm -qf --queryformat "%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n" ` + path
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", fmt.Errorf("Failed to SSH: %s", r)
	}
	fqpn := strings.TrimSpace(r.Stdout)
	return strings.Replace(fqpn, "-(none):", "-", -1), nil
}

func (o *redhatBase) hasYumColorOption() bool {
	cmd := "yum --help | grep color"
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	return len(r.Stdout) > 0
}
