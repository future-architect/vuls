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
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"

	"github.com/k0kubun/pp"
)

// inherit OsTypeInterface
type redhat struct {
	base
}

// NewRedhat is constructor
func newRedhat(c config.ServerInfo) *redhat {
	r := &redhat{}
	r.log = util.NewCustomLogger(c)
	r.setServerInfo(c)
	return r
}

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (itsMe bool, red osTypeInterface) {
	red = newRedhat(c)

	if r := exec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		red.setDistro("fedora", "unknown")
		Log.Warn("Fedora not tested yet: %s", r)
		return true, red
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
				Log.Warn("Failed to parse RedHat/CentOS version: %s", r)
				return true, red
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				red.setDistro("centos", release)
			default:
				red.setDistro("rhel", release)
			}
			return true, red
		}
		return true, red
	}

	if r := exec(c, "ls /etc/system-release", noSudo); r.isSuccess() {
		family := "amazon"
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

	Log.Debugf("Not RedHat like Linux. servername: %s", c.ServerName)
	return false, red
}

func (o *redhat) checkIfSudoNoPasswd() error {
	majorVersion, err := o.Distro.MajorVersion()
	if err != nil {
		return fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
	}

	cmd := "yum --version"
	if o.Distro.Family == "centos" && majorVersion < 6 {
		cmd = "echo N | " + cmd
	}
	r := o.exec(cmd, o.sudo())
	if !r.isSuccess() {
		o.log.Errorf("sudo error on %s", r)
		return fmt.Errorf("Failed to sudo: %s", r)
	}
	o.log.Infof("sudo ... OK")
	return nil
}

// CentOS 5 ... yum-changelog
// CentOS 6 ... yum-plugin-changelog
// CentOS 7 ... yum-plugin-changelog
// RHEL, Amazon ... no additinal packages needed
func (o *redhat) checkDependencies() error {
	switch o.Distro.Family {
	case "rhel", "amazon":
		//  o.log.Infof("Nothing to do")
		return nil

	case "centos":
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil {
			return fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
		}

		var name = "yum-plugin-changelog"
		if majorVersion < 6 {
			name = "yum-changelog"
		}

		cmd := "rpm -q " + name
		if r := o.exec(cmd, noSudo); r.isSuccess() {
			return nil
		}
		o.lackDependencies = []string{name}
		return nil

	default:
		return fmt.Errorf("Not implemented yet: %s", o.Distro)
	}
}

func (o *redhat) install() error {
	for _, name := range o.lackDependencies {
		cmd := util.PrependProxyEnv("yum install -y " + name)
		if r := o.exec(cmd, sudo); !r.isSuccess() {
			return fmt.Errorf("Failed to SSH: %s", r)
		}
		o.log.Infof("Installed: %s", name)
	}
	return nil
}

func (o *redhat) checkRequiredPackagesInstalled() error {
	if o.Distro.Family == "centos" {
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil {
			msg := fmt.Sprintf("Not implemented yet: %s, err: %s", o.Distro, err)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}

		var packName = "yum-plugin-changelog"
		if majorVersion < 6 {
			packName = "yum-changelog"
		}

		cmd := "rpm -q " + packName
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("%s is not installed", packName)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}
	return nil
}

func (o *redhat) scanPackages() error {
	var err error
	var packs []models.PackageInfo
	if packs, err = o.scanInstalledPackages(); err != nil {
		o.log.Errorf("Failed to scan installed packages")
		return err
	}
	o.setPackages(packs)

	var vinfos []models.VulnInfo
	if vinfos, err = o.scanVulnInfos(); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages")
		return err
	}
	o.setVulnInfos(vinfos)
	return nil
}

func (o *redhat) scanInstalledPackages() (installedPackages models.PackageInfoList, err error) {
	cmd := "rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\n'"
	r := o.exec(cmd, noSudo)
	if r.isSuccess() {
		//  e.g.
		// openssl	1.0.1e	30.el6.11
		lines := strings.Split(r.Stdout, "\n")
		for _, line := range lines {
			if trimed := strings.TrimSpace(line); len(trimed) != 0 {
				var packinfo models.PackageInfo
				if packinfo, err = o.parseScannedPackagesLine(line); err != nil {
					return
				}
				installedPackages = append(installedPackages, packinfo)
			}
		}
		return
	}

	return installedPackages, fmt.Errorf(
		"Scan packages failed. status: %d, stdout: %s, stderr: %s",
		r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *redhat) parseScannedPackagesLine(line string) (models.PackageInfo, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return models.PackageInfo{},
			fmt.Errorf("Failed to parse package line: %s", line)
	}
	return models.PackageInfo{
		Name:    fields[0],
		Version: fields[1],
		Release: fields[2],
	}, nil
}

func (o *redhat) scanVulnInfos() ([]models.VulnInfo, error) {
	if o.Distro.Family != "centos" {
		// Amazon, RHEL has yum updateinfo as default
		// yum updateinfo can collenct vendor advisory information.
		return o.scanUnsecurePackagesUsingYumPluginSecurity()
	}
	// CentOS does not have security channel...
	// So, yum check-update then parse chnagelog.
	return o.scanUnsecurePackagesUsingYumCheckUpdate()
}

// For CentOS
func (o *redhat) scanUnsecurePackagesUsingYumCheckUpdate() (models.VulnInfos, error) {
	cmd := "LANGUAGE=en_US.UTF-8 yum --color=never %s check-update"
	if o.getServerInfo().Enablerepo != "" {
		cmd = fmt.Sprintf(cmd, "--enablerepo="+o.getServerInfo().Enablerepo)
	} else {
		cmd = fmt.Sprintf(cmd, "")
	}

	r := o.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess(0, 100) {
		//returns an exit code of 100 if there are available updates.
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// get Updateble package name, installed, candidate version.
	packInfoList, err := o.parseYumCheckUpdateLines(r.Stdout)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s. err: %s", cmd, err)
	}
	o.log.Debugf("%s", pp.Sprintf("%v", packInfoList))

	// set candidate version info
	o.Packages.MergeNewVersion(packInfoList)

	// Collect CVE-IDs in changelog
	type PackInfoCveIDs struct {
		PackInfo models.PackageInfo
		CveIDs   []string
	}

	allChangelog, err := o.getAllChangelog(packInfoList)
	if err != nil {
		o.log.Errorf("Failed to getAllchangelog. err: %s", err)
		return nil, err
	}

	// { packageName: changelog-lines }
	var rpm2changelog map[string]*string
	rpm2changelog, err = o.parseAllChangelog(allChangelog)
	if err != nil {
		return nil, fmt.Errorf("Failed to parseAllChangelog. err: %s", err)
	}

	var results []PackInfoCveIDs
	for i, packInfo := range packInfoList {
		changelog := o.getChangelogCVELines(rpm2changelog, packInfo)

		// Collect unique set of CVE-ID in each changelog
		uniqueCveIDMap := make(map[string]bool)
		lines := strings.Split(changelog, "\n")
		for _, line := range lines {
			cveIDs := o.parseYumUpdateinfoLineToGetCveIDs(line)
			for _, c := range cveIDs {
				uniqueCveIDMap[c] = true
			}
		}

		// keys
		var cveIDs []string
		for k := range uniqueCveIDMap {
			cveIDs = append(cveIDs, k)
		}
		p := PackInfoCveIDs{
			PackInfo: packInfo,
			CveIDs:   cveIDs,
		}
		results = append(results, p)

		o.log.Infof("(%d/%d) Scanned %s-%s-%s -> %s-%s : %s",
			i+1,
			len(packInfoList),
			p.PackInfo.Name,
			p.PackInfo.Version,
			p.PackInfo.Release,
			p.PackInfo.NewVersion,
			p.PackInfo.NewRelease,
			p.CveIDs)
	}

	// transform datastructure
	// - From
	// [
	//   {
	//     PackInfo:    models.PackageInfo,
	//     CveIDs:      []string,
	//   },
	// ]
	// - To
	// map {
	//   CveID: []models.PackageInfo
	// }
	cveIDPackInfoMap := make(map[string][]models.PackageInfo)
	for _, res := range results {
		for _, cveID := range res.CveIDs {
			cveIDPackInfoMap[cveID] = append(
				cveIDPackInfoMap[cveID], res.PackInfo)
		}
	}

	vinfos := []models.VulnInfo{}
	for k, v := range cveIDPackInfoMap {
		// Amazon, RHEL do not use this method, so VendorAdvisory do not set.
		vinfos = append(vinfos, models.VulnInfo{
			CveID:    k,
			Packages: v,
		})
	}
	return vinfos, nil
}

// parseYumCheckUpdateLines parse yum check-update to get package name, candidate version
func (o *redhat) parseYumCheckUpdateLines(stdout string) (results models.PackageInfoList, err error) {
	needToParse := false
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		// update information of packages begin after blank line.
		if trimed := strings.TrimSpace(line); len(trimed) == 0 {
			needToParse = true
			continue
		}
		if needToParse {
			if strings.HasPrefix(line, "Obsoleting") ||
				strings.HasPrefix(line, "Security:") {
				// see https://github.com/future-architect/vuls/issues/165
				continue
			}
			candidate, err := o.parseYumCheckUpdateLine(line)
			if err != nil {
				return results, err
			}

			installed, found := o.Packages.FindByName(candidate.Name)
			if !found {
				o.log.Warnf("Not found the package in rpm -qa. candidate: %s-%s-%s",
					candidate.Name, candidate.Version, candidate.Release)
				results = append(results, candidate)
				continue
			}
			installed.NewVersion = candidate.NewVersion
			installed.NewRelease = candidate.NewRelease
			installed.Repository = candidate.Repository
			results = append(results, installed)
		}
	}
	return
}

func (o *redhat) parseYumCheckUpdateLine(line string) (models.PackageInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return models.PackageInfo{}, fmt.Errorf("Unknown format: %s", line)
	}
	splitted := strings.Split(fields[0], ".")
	packName := ""
	if len(splitted) == 1 {
		packName = fields[0]
	} else {
		packName = strings.Join(strings.Split(fields[0], ".")[0:(len(splitted)-1)], ".")
	}

	verfields := strings.Split(fields[1], "-")
	if len(verfields) != 2 {
		return models.PackageInfo{}, fmt.Errorf("Unknown format: %s", line)
	}
	version := o.regexpReplace(verfields[0], `^[0-9]+:`, "")
	release := verfields[1]
	repos := strings.Join(fields[2:len(fields)], " ")

	return models.PackageInfo{
		Name:       packName,
		NewVersion: version,
		NewRelease: release,
		Repository: repos,
	}, nil
}

func (o *redhat) mkPstring() *string {
	str := ""
	return &str
}

func (o *redhat) regexpReplace(src string, pat string, rep string) string {
	re := regexp.MustCompile(pat)
	return re.ReplaceAllString(src, rep)
}

var changeLogCVEPattern = regexp.MustCompile(`CVE-[0-9]+-[0-9]+`)

func (o *redhat) getChangelogCVELines(rpm2changelog map[string]*string, packInfo models.PackageInfo) string {
	rpm := fmt.Sprintf("%s-%s-%s", packInfo.Name, packInfo.NewVersion, packInfo.NewRelease)
	retLine := ""
	if rpm2changelog[rpm] != nil {
		lines := strings.Split(*rpm2changelog[rpm], "\n")
		for _, line := range lines {
			if changeLogCVEPattern.MatchString(line) {
				retLine += fmt.Sprintf("%s\n", line)
			}
		}
	}
	return retLine
}

func (o *redhat) parseAllChangelog(allChangelog string) (map[string]*string, error) {
	var majorVersion int
	var err error
	if o.Distro.Family == "centos" {
		majorVersion, err = o.Distro.MajorVersion()
		if err != nil {
			return nil, fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
		}
	}

	orglines := strings.Split(allChangelog, "\n")
	tmpline := ""
	var lines []string
	var prev, now bool
	for i := range orglines {
		if majorVersion == 5 {
			/* for CentOS5 (yum-util < 1.1.20) */
			prev = false
			now = false
			if 0 < i {
				prev, err = o.isRpmPackageNameLine(orglines[i-1])
				if err != nil {
					return nil, err
				}
			}
			now, err = o.isRpmPackageNameLine(orglines[i])
			if err != nil {
				return nil, err
			}
			if prev && now {
				tmpline = fmt.Sprintf("%s, %s", tmpline, orglines[i])
				continue
			}
			if !prev && now {
				tmpline = fmt.Sprintf("%s%s", tmpline, orglines[i])
				continue
			}
			if tmpline != "" {
				lines = append(lines, fmt.Sprintf("%s", tmpline))
				tmpline = ""
			}
			lines = append(lines, fmt.Sprintf("%s", orglines[i]))
		} else {
			/* for CentOS6,7 (yum-util >= 1.1.20) */
			line := orglines[i]
			line = o.regexpReplace(line, `^ChangeLog for: `, "")
			line = o.regexpReplace(line, `^\*\*\sNo\sChangeLog\sfor:.*`, "")
			lines = append(lines, line)
		}
	}

	rpm2changelog := make(map[string]*string)
	writePointer := o.mkPstring()
	for _, line := range lines {
		match, err := o.isRpmPackageNameLine(line)
		if err != nil {
			return nil, err
		}
		if match {
			rpms := strings.Split(line, ",")
			pNewString := o.mkPstring()
			writePointer = pNewString
			for _, rpm := range rpms {
				rpm = strings.TrimSpace(rpm)
				rpm = o.regexpReplace(rpm, `^[0-9]+:`, "")
				rpm = o.regexpReplace(rpm, `\.(i386|i486|i586|i686|k6|athlon|x86_64|noarch|ppc|alpha|sparc)$`, "")
				rpm2changelog[rpm] = pNewString
			}
		} else {
			if strings.HasPrefix(line, "Dependencies Resolved") {
				return rpm2changelog, nil
			}
			*writePointer += fmt.Sprintf("%s\n", line)
		}
	}
	return rpm2changelog, nil
}

// CentOS
func (o *redhat) getAllChangelog(packInfoList models.PackageInfoList) (stdout string, err error) {
	packageNames := ""
	for _, packInfo := range packInfoList {
		packageNames += fmt.Sprintf("%s ", packInfo.Name)
	}

	command := ""
	if 0 < len(config.Conf.HTTPProxy) {
		command += util.ProxyEnv()
	}

	yumopts := ""
	if o.getServerInfo().Enablerepo != "" {
		yumopts = " --enablerepo=" + o.getServerInfo().Enablerepo
	}
	if config.Conf.SkipBroken {
		yumopts += " --skip-broken"
	}

	// CentOS 5 does not have --assumeno option.
	majorVersion, _ := o.Distro.MajorVersion()
	if majorVersion < 6 {
		command = "echo N | " + command
	} else {
		yumopts += " --assumeno"
	}

	// yum update --changelog doesn't have --color option.
	command += fmt.Sprintf(" LANGUAGE=en_US.UTF-8 yum %s --changelog update ", yumopts) + packageNames

	r := o.exec(command, sudo)
	if !r.isSuccess(0, 1) {
		return "", fmt.Errorf(
			"Failed to get changelog. status: %d, stdout: %s, stderr: %s",
			r.ExitStatus, r.Stdout, r.Stderr)
	}
	return r.Stdout, nil
}

type distroAdvisoryCveIDs struct {
	DistroAdvisory models.DistroAdvisory
	CveIDs         []string
}

// Scaning unsecure packages using yum-plugin-security.
// Amazon, RHEL
func (o *redhat) scanUnsecurePackagesUsingYumPluginSecurity() (models.VulnInfos, error) {
	if o.Distro.Family == "centos" {
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

	// get advisoryID(RHSA, ALAS) - package name,version
	major, err := (o.Distro.MajorVersion())
	if err != nil {
		return nil, fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
	}

	if o.Distro.Family == "rhel" && major == 5 {
		cmd = "yum --color=never list-security --security"
	} else {
		cmd = "yum --color=never --security updateinfo list updates"
	}
	r = o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	advIDPackNamesList, err := o.parseYumUpdateinfoListAvailable(r.Stdout)

	// get package name, version, rel to be upgrade.
	//  cmd = "yum check-update --security"
	cmd = "LANGUAGE=en_US.UTF-8 yum --color=never check-update"
	r = o.exec(util.PrependProxyEnv(cmd), o.sudo())
	if !r.isSuccess(0, 100) {
		//returns an exit code of 100 if there are available updates.
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	updatable, err := o.parseYumCheckUpdateLines(r.Stdout)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s. err: %s", cmd, err)
	}
	o.log.Debugf("%s", pp.Sprintf("%v", updatable))

	// set candidate version info
	o.Packages.MergeNewVersion(updatable)

	dict := map[string][]models.PackageInfo{}
	for _, advIDPackNames := range advIDPackNamesList {
		packInfoList := models.PackageInfoList{}
		for _, packName := range advIDPackNames.PackNames {
			packInfo, found := updatable.FindByName(packName)
			if !found {
				return nil, fmt.Errorf(
					"PackInfo not found. packInfo: %#v", packName)
			}
			packInfoList = append(packInfoList, packInfo)
			continue
		}
		dict[advIDPackNames.AdvisoryID] = packInfoList
	}

	// get advisoryID(RHSA, ALAS) - CVE IDs
	if o.Distro.Family == "rhel" && major == 5 {
		cmd = "yum --color=never info-sec"
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
	//  pp.Println(advisoryCveIDsList)

	// All information collected.
	// Convert to VulnInfos.
	vinfos := models.VulnInfos{}
	for _, advIDCveIDs := range advisoryCveIDsList {
		for _, cveID := range advIDCveIDs.CveIDs {
			found := false
			for i, p := range vinfos {
				if cveID == p.CveID {
					advAppended := append(p.DistroAdvisories, advIDCveIDs.DistroAdvisory)
					vinfos[i].DistroAdvisories = advAppended

					packs := dict[advIDCveIDs.DistroAdvisory.AdvisoryID]
					vinfos[i].Packages = append(vinfos[i].Packages, packs...)
					found = true
					break
				}
			}

			if !found {
				cpinfo := models.VulnInfo{
					CveID:            cveID,
					DistroAdvisories: []models.DistroAdvisory{advIDCveIDs.DistroAdvisory},
					Packages:         dict[advIDCveIDs.DistroAdvisory.AdvisoryID],
				}
				vinfos = append(vinfos, cpinfo)
			}

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
				sort.Strings(foundCveIDs)
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
			case "centos":
				// CentOS has no security channel.
				// So use yum check-update && parse changelog
				return result, fmt.Errorf(
					"yum updateinfo is not suppported on  CentOS")
			case "rhel", "amazon":
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

// parseYumUpdateinfoListAvailable collect AdvisorID(RHSA, ALAS), packages
func (o *redhat) parseYumUpdateinfoListAvailable(stdout string) (advisoryIDPacksList, error) {
	result := []advisoryIDPacks{}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {

		if !(strings.HasPrefix(line, "RHSA") ||
			strings.HasPrefix(line, "ALAS")) {
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
	case "amazon":
		return false
	default:
		return true
	}
}
