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

// inherit OsTypeInterface
type redhat struct {
	base
}

// NewRedhat is constructor
func newRedhat(c config.ServerInfo) *redhat {
	r := &redhat{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (itsMe bool, red osTypeInterface) {
	red = newRedhat(c)

	// Need to discover Oracle Linux first, because it provides an
	// /etc/redhat-release that matches the upstream distribution
	releases := []string{
		"/etc/oracle-release",
		"/etc/fedora-release",
		"/etc/redhat-release",
		"/etc/system-release",
	}

	for _, dist := range releases {
		if r := exec(c, "cat "+dist, noSudo); r.isSuccess() {
			// Almost everything can be covered with regular expressions
			re := regexp.MustCompile(`(.*) release (\d[\d\.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))

			if len(result) == 3 {
				release := result[2]

				switch strings.ToLower(strings.Fields(result[1])[0]) {
				case "amazon":
					release = "unknown"
					if strings.HasPrefix(r.Stdout, "Amazon Linux release 2") {
						fields := strings.Fields(r.Stdout)
						release = fmt.Sprintf("%s %s", fields[3], fields[4])
					} else {
						fields := strings.Fields(r.Stdout)
						if len(fields) == 5 {
							release = fields[4]
						}
					}
					red.setDistro(config.Amazon, release)
				case "clearos", "scientific", "springdale":
					// Clones of RHEL are handled equally to CentOS
					util.Log.Warnf("%s is handled equally to CentOS", result[1])
					fallthrough
				case "centos":
					red.setDistro(config.CentOS, release)
				case "fedora":
					// Fedora Core is too old
					if strings.HasPrefix(result[1], "Fedora Core") {
						util.Log.Warnf("%s is not supported forever. servername: %s", result[1], c.ServerName)
						return false, red
					}
					red.setDistro(config.Fedora, release)
				case "oracle":
					red.setDistro(config.Oracle, release)
				case "pu_ias":
					util.Log.Warnf("%s is not supported", result[1])
					return false, red
				case "red":
					// Red Flag Linux does not satisfy regular expressions
					// but Red Hat Linux (not RHEL) will match the regular expression
					if strings.HasPrefix(result[1], "Red Hat Linux") {
						util.Log.Warnf("%s (not RHEL) is not supported forever. servername: %s", result[1], c.ServerName)
						return false, red
					}
					red.setDistro(config.RedHat, release)
				default:
					util.Log.Warnf("Failed to parse RedHat like Linux version: %s", r)
				}
				return true, red
			}
		}
	}

	util.Log.Debugf("Not RedHat like Linux. servername: %s", c.ServerName)
	return false, red
}

func (o *redhat) checkIfSudoNoPasswd() error {
	if !config.Conf.Deep || !o.sudo() {
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
				{"yum --color=never info-security --security", zero},
			}
		} else {
			cmds = []cmd{
				{"yum --color=never repolist", zero},
				{"yum --color=never updateinfo -q list --security updates", zero},
				{"yum --color=never updateinfo -q info --security updates", zero},
			}
		}

		if o.Distro.Family == config.RedHat {
			cmds = append(cmds, cmd{"repoquery -h", zero})
		}
	}

	for _, c := range cmds {
		cmd := util.PrependProxyEnv(c.cmd)
		o.log.Infof("Checking... sudo %s", cmd)
		r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
		if !r.isSuccess(c.expectedStatusCodes...) {
			o.log.Errorf("Check sudo or proxy settings: %s", r)
			return fmt.Errorf("Failed to sudo: %s", r)
		}
	}
	o.log.Infof("Sudo... Pass")
	return nil
}

// - Fast scan mode
//    Amazon        ... yum-utils
//
// - Deep scan mode
//    Fedora 7-8    ... yum-utils, yum-security
//    Fedora 9-10   ... yum-utils, yum-security, yum-changelog
//    Fedora 11-20  ... yum-utils, yum-plugin-security, yum-plugin-changelog
//    Fedora 21-22  ... yum-utils, yum-plugin-changelog
//    Fedora 23-27  ... yum, yum-plugin-changelog
//    CentOS 6, 7   ... yum-utils, yum-plugin-changelog
//    RHEL 5 (U1-)  ... yum-utils, yum-security, yum-changelog
//    RHEL 6        ... yum-utils, yum-plugin-security, yum-plugin-changelog
//    RHEL 7        ... yum-utils, yum-plugin-changelog
//    Amazon        ... yum-utils
func (o *redhat) checkDependencies() error {
	majorVersion, err := o.Distro.MajorVersion()
	if err != nil {
		msg := fmt.Sprintf("Not implemented yet: %s, err: %s", o.Distro, err)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	switch o.Distro.Family {
	case config.Fedora:
		if majorVersion < 7 {
			msg := fmt.Sprintf("fedora %s is not supported", o.Distro.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		if majorVersion < 25 {
			msg := fmt.Sprintf("fedora %s is deprecated", o.Distro.Release)
			o.log.Warnf(msg)
		}
	case config.RedHat:
		if majorVersion < 5 {
			msg := fmt.Sprintf("red hat enterprise linux %s is not supported", o.Distro.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	case config.Oracle:
		if majorVersion < 5 {
			msg := fmt.Sprintf("oracle linux %s is not supported", o.Distro.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	case config.CentOS:
		if majorVersion < 5 {
			msg := fmt.Sprintf("%s %s is not supported", o.Distro.Family, o.Distro.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		if majorVersion < 6 {
			msg := fmt.Sprintf("%s %s is deprecated", o.Distro.Family, o.Distro.Release)
			o.log.Warnf(msg)
		}
	}

	packNames := []string{}

	switch o.Distro.Family {
	case config.Fedora:
		switch majorVersion {
		case 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22:
			packNames = append(packNames, "yum-utils")
		default:
			packNames = append(packNames, "yum")
		}
	case config.Amazon:
		packNames = append(packNames, "yum-utils")
	}

	if config.Conf.Deep {
		switch o.Distro.Family {
		case config.Fedora:
			switch majorVersion {
			case 7, 8:
				packNames = append(packNames, "yum-security")
			case 9, 10:
				packNames = append(packNames, "yum-security", "yum-changelog")
			case 11, 12, 13, 14, 15, 16, 17, 18, 19, 20:
				packNames = append(packNames, "yum-plugin-security", "yum-plugin-changelog")
			default:
				packNames = append(packNames, "yum-plugin-changelog")
			}
		case config.CentOS:
			switch majorVersion {
			case 5:
				packNames = append(packNames, "yum-utils", "yum-changelog")
			default:
				packNames = append(packNames, "yum-utils", "yum-plugin-changelog")
			}
		case config.Amazon:
			packNames = append(packNames, "yum-plugin-changelog")
		case config.RedHat, config.Oracle:
			switch majorVersion {
			case 5:
				packNames = append(packNames, "yum-utils", "yum-security", "yum-changelog")
			case 6:
				packNames = append(packNames, "yum-utils", "yum-plugin-security", "yum-plugin-changelog")
			default:
				packNames = append(packNames, "yum-utils", "yum-plugin-changelog")
			}
		default:
			return fmt.Errorf("Not implemented yet: %s", o.Distro)
		}
	}

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

func (o *redhat) scanPackages() error {
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

	if !config.Conf.Deep {
		switch o.Distro.Family {
		case config.Amazon, config.Fedora:
			// OVAL is not supported
		default:
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

func (o *redhat) rebootRequired() (bool, error) {
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

func (o *redhat) scanInstalledPackages() (models.Packages, error) {
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
			if strings.Contains(pack.Name, "kernel") {
				isKernel, running := isRunningKernel(pack, o.Distro.Family, o.Kernel)
				if isKernel {
					if !running {
						o.log.Debugf("Not a running kernel. pack: %#v, kernel: %#v", pack, o.Kernel)
						continue
					}
					o.log.Debugf("Found a running kernel. pack: %#v, kernel: %#v", pack, o.Kernel)
				}
			}
			installed[pack.Name] = pack
		}
	}
	return installed, nil
}

func (o *redhat) parseInstalledPackagesLine(line string) (models.Package, error) {
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

func (o *redhat) scanUpdatablePackages() (models.Packages, error) {
	// Network Connection is required
	cmd := "repoquery"
	majorVersion, _ := o.Distro.MajorVersion()

	switch o.Distro.Family {
	case config.Fedora:
		if majorVersion >= 23 {
			// dnf-plugins-core > 0.1.10
			cmd = "dnf"
		}
	}

	switch cmd {
	case "repoquery":
		cmd = "repoquery -q --all --pkgnarrow=updates --qf=\"%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{REPO}\""
	case "dnf":
		cmd = "dnf --color=never repoquery -q --upgrades --qf=\"%{name} %{epoch} %{version} %{release} %{reponame}\""
	}
	for _, repo := range o.getServerInfo().Enablerepo {
		cmd += " --enablerepo=" + repo
	}
	cmd += " 2>/dev/null"

	r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// Collect Updateble packages, installed, candidate version and repository.
	return o.parseUpdatablePacksLines(r.Stdout)
}

// parseUpdatablePacksLines parse the stdout of repoquery to get package name, candidate version
func (o *redhat) parseUpdatablePacksLines(stdout string) (models.Packages, error) {
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
		}
		pack, err := o.parseUpdatablePacksLine(line)
		if err != nil {
			return updatable, err
		}
		updatable[pack.Name] = pack
	}
	return updatable, nil
}

func (o *redhat) parseUpdatablePacksLine(line string) (models.Package, error) {
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

func (o *redhat) scanUnsecurePackages(updatable models.Packages) (models.VulnInfos, error) {
	majorVersion, _ := o.Distro.MajorVersion()

	if config.Conf.Deep {
		switch o.Distro.Family {
		case config.Amazon:
			// nop
		case config.Fedora:
			if majorVersion < 9 {
				break
			}
			fallthrough
		default:
			//TODO Cache changelogs to bolt
			if err := o.fillChangelogs(updatable); err != nil {
				return nil, err
			}
		}
	}

	switch o.Distro.Family {
	case config.CentOS:
		// Parse chnagelog because CentOS does not have security channel...
		return o.scanCveIDsInChangelog(updatable)
	default:
		// Amazon, RHEL, Oracle Linux, Fedora has yum updateinfo as default
		// yum updateinfo can collenct vendor advisory information.
		return o.scanCveIDsByCommands(updatable)
	}
}

func (o *redhat) fillChangelogs(updatables models.Packages) error {
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

func (o *redhat) getAvailableChangelogs(packNames []string) (map[string]string, error) {
	yum := "yum --color=never"
	yumopts := ""

	majorVersion, _ := o.Distro.MajorVersion()

	switch o.Distro.Family {
	case config.Fedora:
		switch majorVersion {
		case 9, 10:
			// yum < 3.2.21
			yum = "TERM=dumb yum"
		case 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21:
			// nop
		default:
			yum = "yum-deprecated --color=never"
		}
	}

	if 0 < len(o.getServerInfo().Enablerepo) {
		yumopts += " --enablerepo=" + strings.Join(o.getServerInfo().Enablerepo, ",")
	}
	if config.Conf.SkipBroken {
		yumopts += " --skip-broken"
	}
	cmd := yum + ` changelog all %s updates %s | grep -A 1000000 "==================== Updated Packages ===================="`
	cmd += " 2>/dev/null"
	cmd = fmt.Sprintf(cmd, yumopts, strings.Join(packNames, " "))

	r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess(0, 1) {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	return o.divideChangelogsIntoEachPackages(r.Stdout), nil
}

// Divide available change logs of all updatable packages into each package's changelog
func (o *redhat) divideChangelogsIntoEachPackages(stdout string) map[string]string {
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

func (o *redhat) fillDiffChangelogs(packNames []string) error {
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
				epochNameVerRel = fmt.Sprintf("%s:%s-%s",
					epoch, p.Name, ver)
			} else {
				epochNameVerRel = fmt.Sprintf("%s-%s",
					p.Name, p.NewVersion)
			}
			return strings.HasPrefix(s, epochNameVerRel)
		})

		if found {
			diff, err := o.getDiffChangelog(pack, changelogs[s])
			detectionMethod := models.ChangelogExactMatchStr

			if err != nil {
				o.log.Debug(err)
				// Try without epoch
				if index := strings.Index(pack.Version, ":"); 0 < index {
					pack.Version = pack.Version[index+1 : len(pack.Version)]
					o.log.Debug("Try without epoch", pack)
					diff, err = o.getDiffChangelog(pack, changelogs[s])
					if err != nil {
						o.log.Debugf("Failed to find the version in changelog: %s-%s-%s",
							pack.Name, pack.Version, pack.Release)
						detectionMethod = models.FailedToFindVersionInChangelog
					} else {
						o.log.Debugf("Found the version in changelog without epoch: %s-%s-%s",
							pack.Name, pack.Version, pack.Release)
						detectionMethod = models.ChangelogLenientMatchStr
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

func (o *redhat) getDiffChangelog(pack models.Package, availableChangelog string) (string, error) {
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

func (o *redhat) scanCveIDsInChangelog(updatable models.Packages) (models.VulnInfos, error) {
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
					Confidence:       models.ChangelogExactMatch,
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
// Amazon, RHEL, Oracle Linux, Fedora
func (o *redhat) scanCveIDsByCommands(updatable models.Packages) (models.VulnInfos, error) {
	yum := "yum --color=never"
	updateinfo := true

	major, err := (o.Distro.MajorVersion())
	if err != nil {
		return nil, fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
	}

	switch o.Distro.Family {
	case config.RedHat, config.Oracle:
		switch major {
		case 5:
			updateinfo = false
		}
	case config.CentOS:
		// not supported yet
		switch major {
		case 5:
			updateinfo = false
			name := "yum-security"
			cmd := "rpm -q " + name
			if r := o.exec(cmd, noSudo); !r.isSuccess() {
				return nil, fmt.Errorf("%s is not installed", name)
			}
		}
	case config.Fedora:
		switch major {
		case 7, 8, 9, 10:
			// yum < 3.2.21
			yum = "TERM=dumb yum"
			// yum-plugin-changelog < 1.1.28
			updateinfo = false
		case 11, 12:
			// yum-plugin-changelog < 1.1.28
			updateinfo = false
		case 13, 14, 15, 16, 17, 18, 19, 20, 21:
			// nop
		default:
			yum = "dnf --color=never"
		}
	}

	cmd := yum + " repolist -q 2>/dev/null"
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// get advisoryID(RHSA, ALAS, ELSA, FEDORA) - package name,version
	cmd = "LANG=C "
	if yum == "dnf --color=never" {
		cmd += yum + " updateinfo -q list updates security"
	} else if updateinfo {
		cmd += yum + " updateinfo -q list --security updates"
	} else {
		cmd += yum + " list-security --security"
	}
	cmd += " 2>/dev/null"
	r = o.exec(util.PrependProxyEnv(cmd), o.sudo())
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

	// get advisoryID(RHSA, ALAS, ELSA, FEDORA) - CVE IDs
	cmd = "LANG=C "
	if yum == "dnf --color=never" {
		cmd += yum + " updateinfo -q info updates security"
	} else if updateinfo {
		cmd += yum + " updateinfo -q info --security updates"
	} else {
		cmd += yum + " info-security --security"
	}
	cmd += " 2>/dev/null"
	r = o.exec(util.PrependProxyEnv(cmd), o.sudo())
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
					Confidence:       models.YumUpdateSecurityMatch,
				}
			}
			vinfos[cveID] = vinfo
		}
	}
	return vinfos, nil
}

var horizontalRulePattern = regexp.MustCompile(`^=+$`)

func (o *redhat) parseYumUpdateinfo(stdout string) (result []distroAdvisoryCveIDs, err error) {
	sectionState := Outside
	lines := strings.Split(stdout, "\n")
	lines = append(lines, "=============")

	// Amazon Linux AMI Security Information
	advisory := models.DistroAdvisory{}

	cveIDsSetInThisSection := make(map[string]bool)

	// use this flag to Collect CVE IDs in Description / CVEs / Bugs field.
	inDesctiption, inCves, inBugs := false, false, false

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
				inDesctiption, inCves, inBugs = false, false, false
				advisory = models.DistroAdvisory{}
			}

			// Go to next section
			sectionState = o.changeSectionState(sectionState)
			continue
		}

		switch sectionState {
		case Header:
			// nop
		case Content:
			if found := o.isDescriptionLine(line); found {
				inDesctiption, inCves, inBugs = true, false, false
				ss := strings.Split(line, " : ")
				advisory.Description += fmt.Sprintf("%s\n",
					strings.Join(ss[1:], " : "))
				cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
				for _, cveID := range cveIDs {
					cveIDsSetInThisSection[cveID] = true
				}
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
				cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
				for _, cveID := range cveIDs {
					cveIDsSetInThisSection[cveID] = true
				}
				continue
			}

			if found := o.isBugsHeaderLine(line); found {
				inDesctiption, inCves, inBugs = false, false, true
				//ss := strings.Split(line, "Bugs : ")
				//line = strings.Join(ss[1:], " ")
				cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
				for _, cveID := range cveIDs {
					cveIDsSetInThisSection[cveID] = true
				}
				continue
			}

			if found := o.isCvesHeaderLine(line); found {
				inDesctiption, inCves, inBugs = false, true, false
				//ss := strings.Split(line, "CVEs : ")
				//line = strings.Join(ss[1:], " ")
				cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
				for _, cveID := range cveIDs {
					cveIDsSetInThisSection[cveID] = true
				}
				continue
			}

			if inCves || inBugs {
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

func (o *redhat) changeSectionState(state int) (newState int) {
	switch state {
	case Outside, Content:
		newState = Header
	case Header:
		newState = Content
	}
	return newState
}

func (o *redhat) isBugsHeaderLine(line string) bool {
	return strings.Contains(line, "Bugs : ")
}

func (o *redhat) isCvesHeaderLine(line string) bool {
	return strings.Contains(line, "CVEs : ")
}

var yumCveIDPattern = regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)

func (o *redhat) parseYumUpdateinfoLineToGetCveIDs(line string) []string {
	return yumCveIDPattern.FindAllString(line, -1)
}

var yumAdvisoryIDPattern = regexp.MustCompile(`^ *Update ID : (.*)$`)

func (o *redhat) parseYumUpdateinfoToGetAdvisoryID(line string) (advisoryID string, found bool) {
	result := yumAdvisoryIDPattern.FindStringSubmatch(line)
	if len(result) != 2 {
		return "", false
	}
	return strings.TrimSpace(result[1]), true
}

var yumIssuedPattern = regexp.MustCompile(`^\s*Issued : (\d{4}-\d{2}-\d{2})`)

func (o *redhat) parseYumUpdateinfoLineToGetIssued(line string) (date time.Time, found bool) {
	return o.parseYumUpdateinfoLineToGetDate(line, yumIssuedPattern)
}

var yumUpdatedPattern = regexp.MustCompile(`^\s*Updated : (\d{4}-\d{2}-\d{2})`)

func (o *redhat) parseYumUpdateinfoLineToGetUpdated(line string) (date time.Time, found bool) {
	return o.parseYumUpdateinfoLineToGetDate(line, yumUpdatedPattern)
}

func (o *redhat) parseYumUpdateinfoLineToGetDate(line string, regexpPattern *regexp.Regexp) (date time.Time, found bool) {
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

func (o *redhat) isDescriptionLine(line string) bool {
	return yumDescriptionPattern.MatchString(line)
}

var yumSeverityPattern = regexp.MustCompile(`^ *Severity : (.*)$`)

func (o *redhat) parseYumUpdateinfoToGetSeverity(line string) (severity string, found bool) {
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
func (o *redhat) extractPackNameVerRel(nameVerRel string) (name, ver, rel string) {
	fields := strings.Split(nameVerRel, ".")
	archTrimed := strings.Join(fields[0:len(fields)-1], ".")

	fields = strings.Split(archTrimed, "-")
	rel = fields[len(fields)-1]
	ver = fields[len(fields)-2]
	name = strings.Join(fields[0:(len(fields)-2)], "-")
	return
}

// parseYumUpdateinfoListAvailable collect AdvisorID(RHSA, ALAS, ELSA, FEDORA), packages
func (o *redhat) parseYumUpdateinfoListAvailable(stdout string) (advisoryIDPacksList, error) {
	result := []advisoryIDPacks{}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {

		if !(strings.HasPrefix(line, "RHSA") ||
			strings.HasPrefix(line, "ALAS") ||
			strings.HasPrefix(line, "ELSA") ||
			strings.HasPrefix(line, "FEDORA")) {
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

func (o *redhat) clone() osTypeInterface {
	return o
}

func (o *redhat) sudo() bool {
	switch o.Distro.Family {
	case config.RedHat, config.Oracle:
		// RHEL, Oracle
		return config.Conf.Deep
	}

	return false
}
