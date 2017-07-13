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
	ver "github.com/knqyf263/go-deb-version"
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

	if r := exec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		red.setDistro(config.Fedora, "unknown")
		util.Log.Warn("Fedora not tested yet: %s", r)
		return true, red
	}

	if r := exec(c, "ls /etc/oracle-release", noSudo); r.isSuccess() {
		// Need to discover Oracle Linux first, because it provides an
		// /etc/redhat-release that matches the upstream distribution
		if r := exec(c, "cat /etc/oracle-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				util.Log.Warn("Failed to parse Oracle Linux version: %s", r)
				return true, red
			}

			release := result[2]
			red.setDistro(config.Oracle, release)
			return true, red
		}
	}

	if r := exec(c, "ls /etc/redhat-release", noSudo); r.isSuccess() {
		// https://www.rackaid.com/blog/how-to-determine-centos-or-red-hat-version/
		// e.g.
		// $ cat /etc/redhat-release
		// CentOS release 6.5 (Final)
		if r := exec(c, "cat /etc/redhat-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				util.Log.Warn("Failed to parse RedHat/CentOS version: %s", r)
				return true, red
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				red.setDistro(config.CentOS, release)
			default:
				red.setDistro(config.RedHat, release)
			}
			return true, red
		}
		return true, red
	}

	if r := exec(c, "ls /etc/system-release", noSudo); r.isSuccess() {
		family := config.Amazon
		release := "unknown"
		if r := exec(c, "cat /etc/system-release", noSudo); r.isSuccess() {
			fields := strings.Fields(r.Stdout)
			if len(fields) == 5 {
				release = fields[4]
			}
		}
		red.setDistro(family, release)
		return true, red
	}

	util.Log.Debugf("Not RedHat like Linux. servername: %s", c.ServerName)
	return false, red
}

func (o *redhat) checkIfSudoNoPasswd() error {
	if !o.sudo() {
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
	case config.CentOS:
		cmds = []cmd{
			{"yum --changelog --assumeno update yum", []int{0, 1}},
		}

	case config.RedHat, config.Oracle:
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil {
			return fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
		}

		if majorVersion < 6 {
			cmds = []cmd{
				{"yum --color=never repolist", zero},
				// {"yum --color=never check-update", []int{0, 100}},
				{"yum --color=never list-security --security", zero},
				{"yum --color=never info-security", zero},
			}
		} else {
			cmds = []cmd{
				//TODO repoquery
				{"yum --color=never repolist", zero},
				// {"yum --color=never check-update", []int{0, 100}},
				{"yum --color=never --security updateinfo list updates", zero},
				{"yum --color=never --security updateinfo updates", zero},
			}
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

// CentOS 6, 7 	... yum-plugin-changelog, yum-utils
// RHEL 5     	... yum-security
// RHEL 6, 7    ... -
// Amazon 		... -
func (o *redhat) checkDependencies() error {
	if o.Distro.Family == config.Amazon {
		return nil
	}

	majorVersion, err := o.Distro.MajorVersion()
	if err != nil {
		msg := fmt.Sprintf("Not implemented yet: %s, err: %s", o.Distro, err)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	if o.Distro.Family == config.CentOS {
		if majorVersion < 6 {
			msg := fmt.Sprintf("CentOS %s is not supported", o.Distro.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}

		// --assumeno option of yum is needed.
		cmd := "yum -h | grep assumeno"
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("Installed yum is old. Please update yum and then retry")
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}

	var packNames []string
	switch o.Distro.Family {
	case config.CentOS:
		packNames = []string{"yum-plugin-changelog", "yum-utils"}
	case config.RedHat, config.Oracle:
		if majorVersion < 6 {
			packNames = []string{"yum-security"}
		} else {
			// yum-plugin-security is installed by default on RHEL6, 7
			return nil
		}
	default:
		return fmt.Errorf("Not implemented yet: %s", o.Distro)
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
		o.log.Errorf("Failed to scan installed packages")
		return err
	}

	updatable, err := o.scanUpdatablePackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages")
		return err
	}
	installed.MergeNewVersion(updatable)
	o.setPackages(installed)

	if config.Conf.PackageListOnly {
		return nil
	}

	var vinfos models.VulnInfos
	if vinfos, err = o.scanUnsecurePackages(updatable); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages")
		return err
	}
	o.setVulnInfos(vinfos)
	return nil
}

func (o *redhat) scanInstalledPackages() (models.Packages, error) {
	installed := models.Packages{}
	// cmd := "repoquery --all --pkgnarrow=installed --qf='%{NAME} %{EPOCH} %{VERSION} %{RELEASE}'"
	cmd := "rpm -qa --queryformat '%{NAME} %{EPOCHNUM} %{VERSION} %{RELEASE}\n'"
	r := o.exec(cmd, noSudo)
	if r.isSuccess() {
		// openssl 0 1.0.1e	30.el6.11 base
		lines := strings.Split(r.Stdout, "\n")
		for _, line := range lines {
			if trimed := strings.TrimSpace(line); len(trimed) != 0 {
				pack, err := o.parseInstalledPackagesLine(line)
				if err != nil {
					return nil, err
				}
				installed[pack.Name] = pack
			}
		}
		return installed, nil
	}

	return nil, fmt.Errorf("Scan packages failed. status: %d, stdout: %s, stderr: %s",
		r.ExitStatus, r.Stdout, r.Stderr)

}

func (o *redhat) parseInstalledPackagesLine(line string) (models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return models.Package{},
			fmt.Errorf("Failed to parse package line: %s", line)
	}
	ver := ""
	epoch := fields[1]
	if epoch == "0" {
		ver = fields[2]
	} else {
		ver = fmt.Sprintf("%s:%s", epoch, fields[2])
	}

	return models.Package{
		Name:    fields[0],
		Version: ver,
		Release: fields[3],
	}, nil
}

func (o *redhat) scanUpdatablePackages() (models.Packages, error) {
	cmd := "repoquery --all --pkgnarrow=updates --qf='%{NAME} %{EPOCH} %{VERSION} %{RELEASE} %{REPO}'"
	for _, repo := range o.getServerInfo().Enablerepo {
		cmd += " --enablerepo=" + repo
	}

	r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// Collect Updateble packages, installed, candidate version and repository.
	return o.parseScanUpdatablePacksLines(r.Stdout)
}

// parseScanUpdatablePacksLines parse the stdout of repoquery to get package name, candidate version
func (o *redhat) parseScanUpdatablePacksLines(stdout string) (models.Packages, error) {
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
		pack, err := o.parseScanUpdatablePacksLine(line)
		if err != nil {
			return updatable, err
		}
		updatable[pack.Name] = pack
	}
	return updatable, nil
}

func (o *redhat) parseScanUpdatablePacksLine(line string) (models.Package, error) {
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

	repos := strings.Join(fields[4:len(fields)], " ")

	p := models.Package{
		Name:       fields[0],
		NewVersion: ver,
		NewRelease: fields[3],
		Repository: repos,
	}
	return p, nil
}

func (o *redhat) scanUnsecurePackages(updatable models.Packages) (models.VulnInfos, error) {
	if o.Distro.Family != config.CentOS {
		// Amazon, RHEL, Oracle Linux has yum updateinfo as default
		// yum updateinfo can collenct vendor advisory information.
		return o.scanUnsecurePackagesUsingYumPluginSecurity(updatable)
	}
	// CentOS does not have security channel...
	// So, yum check-update then parse chnagelog.
	return o.scanUnsecurePackagesUsingYumCheckUpdate(updatable)
}

func (o *redhat) fillChangelogs(updatables models.Packages) error {
	type response struct {
		packName  string
		changelog string
	}
	reqChan := make(chan string, len(updatables))
	errChan := make(chan error, len(updatables))
	resChan := make(chan response, len(updatables))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, pack := range updatables {
			reqChan <- pack.Name
		}
	}()

	timeout := time.After(10 * 60 * time.Second)
	concurrency := 1
	tasks := util.GenWorkers(concurrency)
	for range updatables {
		tasks <- func() {
			select {
			case packName := <-reqChan:
				func(name string) {
					if changelog, err := o.getAvailableChangelog(name); err != nil {
						errChan <- err
					} else {
						pack := o.Packages[name]
						diff, err := o.getDiffChangelog(pack, changelog)
						if err != nil {
							errChan <- err
						}
						resChan <- response{name, diff}
					}
				}(packName)
			}
		}
	}

	errs := []error{}
	for i := 0; i < len(updatables); i++ {
		select {
		case response := <-resChan:
			p := o.Packages[response.packName]
			p.Changelog = models.Changelog{
				Contents: response.changelog,
				Method:   models.ChangelogExactMatchStr,
			}
			o.Packages[response.packName] = p
			o.log.Infof("(%d/%d) Fetched Changelogs %s", i+1, len(updatables), response.packName)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			errs = append(errs, fmt.Errorf("Timeout scanPackageCveIDs"))
		}
	}
	if 0 < len(errs) {
		return fmt.Errorf("%v", errs)
	}
	return nil
}

func (o *redhat) getAvailableChangelog(packName string) (string, error) {
	yumopts := ""
	if 0 < len(o.getServerInfo().Enablerepo) {
		yumopts = " --enablerepo=" + strings.Join(o.getServerInfo().Enablerepo, ",")
	}
	if config.Conf.SkipBroken {
		yumopts += " --skip-broken"
	}

	cmd := `yum --color=never %s changelog all %s | grep -A 10000 '==================== Available Packages ===================='`
	cmd = fmt.Sprintf(cmd, yumopts, packName)
	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess(0, 1) {
		return "", fmt.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (o *redhat) getDiffChangelog(pack models.Package, availableChangelog string) (string, error) {
	installedVer, err := ver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
	if err != nil {
		return "", fmt.Errorf("Failed to parse installed version: %s", err)
	}

	scanner := bufio.NewScanner(strings.NewReader(availableChangelog))
	diff := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "* ") {
			diff = append(diff, line)
			continue
		}

		ss := strings.Split(line, " ")
		if len(ss) < 2 {
			diff = append(diff, line)
			continue
		}
		v := ss[len(ss)-1]
		v = strings.TrimPrefix(v, "-")
		version, err := ver.NewVersion(v)
		if err != nil {
			o.log.Debugf("Failed to parse version in changelog. %s, err: %s", pack, err)
			continue
		}

		if installedVer.Equal(version) || installedVer.GreaterThan(version) {
			break
		}
		diff = append(diff, line)
	}

	// pp.Println(pack, strings.Split(availableChangelog, "\r\n"), diff)
	if 2 < len(diff) {
		diff = diff[2:len(diff)]
	}
	return strings.TrimSpace(strings.Join(diff, "\n")), nil
}

//TODO rename grepCveIDsFromChangelog
func (o *redhat) scanUnsecurePackagesUsingYumCheckUpdate(updatable models.Packages) (models.VulnInfos, error) {
	//TODO move to appropriate position
	if err := o.fillChangelogs(updatable); err != nil {
		return nil, err
	}

	// TODO goroutine if this logic is too slow
	packCveIDs := make(map[string][]string)
	for name := range updatable {
		cveIDs := []string{}
		scanner := bufio.NewScanner(strings.NewReader(o.Packages[name].Changelog.Contents))
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
				v.PackageNames = append(v.PackageNames, name)
				vinfos[cid] = v
			} else {
				vinfos[cid] = models.VulnInfo{
					CveID:        cid,
					PackageNames: []string{name},
					Confidence:   models.ChangelogExactMatch,
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
func (o *redhat) scanUnsecurePackagesUsingYumPluginSecurity(updatable models.Packages) (models.VulnInfos, error) {
	if o.Distro.Family == config.CentOS {
		// CentOS has no security channel.
		// So use yum check-update && parse changelog
		return nil, fmt.Errorf(
			"yum updateinfo is not suppported on CentOS")
	}

	cmd := "yum --color=never repolist"
	r := o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// get advisoryID(RHSA, ALAS, ELSA) - package name,version
	major, err := (o.Distro.MajorVersion())
	if err != nil {
		return nil, fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
	}

	if (o.Distro.Family == config.RedHat || o.Distro.Family == config.Oracle) && major == 5 {
		cmd = "yum --color=never list-security --security"
	} else {
		cmd = "yum --color=never --security updateinfo list updates"
	}
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

	// get advisoryID(RHSA, ALAS, ELSA) - CVE IDs
	if (o.Distro.Family == config.RedHat || o.Distro.Family == config.Oracle) && major == 5 {
		cmd = "yum --color=never info-security"
	} else {
		cmd = "yum --color=never --security updateinfo updates"
	}
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
					vinfo.PackageNames = append(vinfo.PackageNames, pack.Name)
				}
			} else {
				names := []string{}
				packs := dict[advIDCveIDs.DistroAdvisory.AdvisoryID]
				for _, pack := range packs {
					names = append(names, pack.Name)
				}
				vinfo = models.VulnInfo{
					CveID:            cveID,
					DistroAdvisories: []models.DistroAdvisory{advIDCveIDs.DistroAdvisory},
					PackageNames:     names,
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

	// use this flag to Collect CVE IDs in CVEs field.
	var inDesctiption = false

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
				inDesctiption = false
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
				// So use yum check-update && parse changelog
				return result, fmt.Errorf(
					"yum updateinfo is not suppported on  CentOS")
			case config.RedHat, config.Amazon, config.Oracle:
				// nop
			}

		case Content:
			if found := o.isDescriptionLine(line); found {
				inDesctiption = true
			}

			// severity
			severity, found := o.parseYumUpdateinfoToGetSeverity(line)
			if found {
				advisory.Severity = severity
			}

			// No need to parse in description except severity
			if inDesctiption {
				continue
			}

			cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
			for _, cveID := range cveIDs {
				cveIDsSetInThisSection[cveID] = true
			}

			advisoryID, found := o.parseYumUpdateinfoToGetAdvisoryID(line)
			if found {
				advisory.AdvisoryID = advisoryID
			}

			issued, found := o.parseYumUpdateinfoLineToGetIssued(line)
			if found {
				advisory.Issued = issued
			}

			updated, found := o.parseYumUpdateinfoLineToGetUpdated(line)
			if found {
				advisory.Updated = updated
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

var rpmPackageArchPattern = regexp.MustCompile(
	`^[^ ]+\.(i386|i486|i586|i686|k6|athlon|x86_64|noarch|ppc|alpha|sparc)$`)

func (o *redhat) isRpmPackageNameLine(line string) (bool, error) {
	s := strings.TrimPrefix(line, "ChangeLog for: ")
	ss := strings.Split(s, ", ")
	if len(ss) == 0 {
		return false, nil
	}
	for _, s := range ss {
		s = strings.TrimRight(s, " \r\n")
		if !rpmPackageArchPattern.MatchString(s) {
			return false, nil
		}
	}
	return true, nil
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

// parseYumUpdateinfoListAvailable collect AdvisorID(RHSA, ALAS, ELSA), packages
func (o *redhat) parseYumUpdateinfoListAvailable(stdout string) (advisoryIDPacksList, error) {
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

func (o *redhat) clone() osTypeInterface {
	return o
}

func (o *redhat) sudo() bool {
	switch o.Distro.Family {
	case config.Amazon, config.CentOS:
		return false
	default:
		// RHEL
		return true
	}
}
