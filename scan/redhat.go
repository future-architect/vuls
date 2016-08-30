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
	"strconv"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
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
	return r
}

// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/redhat.rb
func detectRedhat(c config.ServerInfo) (itsMe bool, red osTypeInterface) {
	red = newRedhat(c)
	red.setServerInfo(c)

	if r := sshExec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		red.setDistributionInfo("fedora", "unknown")
		Log.Warn("Fedora not tested yet: %s", r)
		return true, red
	}

	if r := sshExec(c, "ls /etc/redhat-release", noSudo); r.isSuccess() {
		// https://www.rackaid.com/blog/how-to-determine-centos-or-red-hat-version/
		// e.g.
		// $ cat /etc/redhat-release
		// CentOS release 6.5 (Final)
		if r := sshExec(c, "cat /etc/redhat-release", noSudo); r.isSuccess() {
			re := regexp.MustCompile(`(.*) release (\d[\d.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				Log.Warn("Failed to parse RedHat/CentOS version: %s", r)
				return true, red
			}

			release := result[2]
			switch strings.ToLower(result[1]) {
			case "centos", "centos linux":
				red.setDistributionInfo("centos", release)
			default:
				red.setDistributionInfo("rhel", release)
			}
			return true, red
		}
		return true, red
	}

	if r := sshExec(c, "ls /etc/system-release", noSudo); r.isSuccess() {
		family := "amazon"
		release := "unknown"
		if r := sshExec(c, "cat /etc/system-release", noSudo); r.isSuccess() {
			fields := strings.Fields(r.Stdout)
			if len(fields) == 5 {
				release = fields[4]
			}
		}
		red.setDistributionInfo(family, release)
		return true, red
	}

	Log.Debugf("Not RedHat like Linux. servername: %s", c.ServerName)
	return false, red
}

func (o *redhat) checkIfSudoNoPasswd() error {
	r := o.ssh("yum --version", sudo)
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
func (o *redhat) install() error {
	switch o.Family {
	case "rhel", "amazon":
		o.log.Infof("Nothing to do")
		return nil
	}
	// CentOS
	return o.installYumChangelog()
}

func (o *redhat) installYumChangelog() error {
	if o.Family == "centos" {
		var majorVersion int
		if 0 < len(o.Release) {
			majorVersion, _ = strconv.Atoi(strings.Split(o.Release, ".")[0])
		} else {
			return fmt.Errorf(
				"Not implemented yet. family: %s, release: %s",
				o.Family, o.Release)
		}

		var packName = ""
		if majorVersion < 6 {
			packName = "yum-changelog"
		} else {
			packName = "yum-plugin-changelog"
		}

		cmd := "rpm -q " + packName
		if r := o.ssh(cmd, noSudo); r.isSuccess() {
			o.log.Infof("Ignored: %s already installed", packName)
			return nil
		}

		o.log.Infof("Installing %s...", packName)
		cmd = util.PrependProxyEnv("yum install -y " + packName)
		if r := o.ssh(cmd, sudo); !r.isSuccess() {
			return fmt.Errorf("Failed to SSH: %s", r)
		}
		o.log.Infof("Installed: %s", packName)
	}
	return nil
}

func (o *redhat) checkRequiredPackagesInstalled() error {
	if o.Family == "centos" {
		var majorVersion int
		if 0 < len(o.Release) {
			majorVersion, _ = strconv.Atoi(strings.Split(o.Release, ".")[0])
		} else {
			msg := fmt.Sprintf("Not implemented yet. family: %s, release: %s", o.Family, o.Release)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}

		var packName = ""
		if majorVersion < 6 {
			packName = "yum-changelog"
		} else {
			packName = "yum-plugin-changelog"
		}

		cmd := "rpm -q " + packName
		if r := o.ssh(cmd, noSudo); !r.isSuccess() {
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

	var unsecurePacks []CvePacksInfo
	if unsecurePacks, err = o.scanUnsecurePackages(); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages")
		return err
	}
	o.setUnsecurePackages(unsecurePacks)
	return nil
}

func (o *redhat) scanInstalledPackages() (installedPackages models.PackageInfoList, err error) {
	cmd := "rpm -qa --queryformat '%{NAME}\t%{VERSION}\t%{RELEASE}\n'"
	r := o.ssh(cmd, noSudo)
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

func (o *redhat) scanUnsecurePackages() ([]CvePacksInfo, error) {
	if o.Family != "centos" {
		// Amazon, RHEL has yum updateinfo as default
		// yum updateinfo can collenct vendor advisory information.
		return o.scanUnsecurePackagesUsingYumPluginSecurity()
	}
	// CentOS does not have security channel...
	// So, yum check-update then parse chnagelog.
	return o.scanUnsecurePackagesUsingYumCheckUpdate()
}

//TODO return whether already expired.
func (o *redhat) scanUnsecurePackagesUsingYumCheckUpdate() (CvePacksList, error) {
	cmd := "LANG=en_US.UTF-8 yum --color=never check-update"
	r := o.ssh(util.PrependProxyEnv(cmd), sudo)
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

	// Collect CVE-IDs in changelog
	type PackInfoCveIDs struct {
		PackInfo models.PackageInfo
		CveIDs   []string
	}

	// { packageName: changelog-lines }
	var rpm2changelog map[string]*string
	allChangelog, err := o.getAllChangelog(packInfoList)
	if err != nil {
		o.log.Errorf("Failed to getAllchangelog. err: %s", err)
		return nil, err
	}
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
			//  packInfo, found := o.Packages.FindByName(res.Packname)
			//  if !found {
			//      return CvePacksList{}, fmt.Errorf(
			//          "Faild to transform data structure: %v", res.Packname)
			//  }
			cveIDPackInfoMap[cveID] = append(cveIDPackInfoMap[cveID], res.PackInfo)
		}
	}

	var uniqueCveIDs []string
	for cveID := range cveIDPackInfoMap {
		uniqueCveIDs = append(uniqueCveIDs, cveID)
	}

	// cveIDs => []cve.CveInfo
	o.log.Info("Fetching CVE details...")
	cveDetails, err := cveapi.CveClient.FetchCveDetails(uniqueCveIDs)
	if err != nil {
		return nil, err
	}
	o.log.Info("Done")

	cvePacksList := []CvePacksInfo{}
	for _, detail := range cveDetails {
		// Amazon, RHEL do not use this method, so VendorAdvisory do not set.
		cvePacksList = append(cvePacksList, CvePacksInfo{
			CveID:     detail.CveID,
			CveDetail: detail,
			Packs:     cveIDPackInfoMap[detail.CveID],
			//  CvssScore: cinfo.CvssScore(conf.Lang),
		})
	}
	return cvePacksList, nil
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
			if strings.HasPrefix(line, "Obsoleting") {
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
			results = append(results, installed)
		}
	}
	return
}

func (o *redhat) parseYumCheckUpdateLine(line string) (models.PackageInfo, error) {
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return models.PackageInfo{}, fmt.Errorf("Unknown format: %s", line)
	}
	splitted := strings.Split(fields[0], ".")
	packName := ""
	if len(splitted) == 1 {
		packName = fields[0]
	} else {
		packName = strings.Join(strings.Split(fields[0], ".")[0:(len(splitted)-1)], ".")
	}

	fields = strings.Split(fields[1], "-")
	if len(fields) != 2 {
		return models.PackageInfo{}, fmt.Errorf("Unknown format: %s", line)
	}
	version := o.regexpReplace(fields[0], `^[0-9]+:`, "")
	release := fields[1]
	return models.PackageInfo{
		Name:       packName,
		NewVersion: version,
		NewRelease: release,
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
	if 0 < len(o.Release) && o.Family == "centos" {
		majorVersion, _ = strconv.Atoi(strings.Split(o.Release, ".")[0])
	} else {
		return nil, fmt.Errorf(
			"Not implemented yet. family: %s, release: %s",
			o.Family, o.Release)
	}

	orglines := strings.Split(allChangelog, "\n")
	tmpline := ""
	var lines []string
	var prev, now bool
	var err error
	for i := range orglines {
		if majorVersion == 5 {
			/* for CentOS5 (yum-util < 1.1.20) */
			prev = false
			now = false
			if i > 0 {
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

func (o *redhat) getAllChangelog(packInfoList models.PackageInfoList) (stdout string, err error) {
	packageNames := ""
	for _, packInfo := range packInfoList {
		packageNames += fmt.Sprintf("%s ", packInfo.Name)
	}

	command := "echo N | "
	if 0 < len(config.Conf.HTTPProxy) {
		command += util.ProxyEnv()
	}

	// yum update --changelog doesn't have --color option.
	command += fmt.Sprintf(" LANG=en_US.UTF-8 yum update --changelog %s", packageNames)

	r := o.ssh(command, sudo)
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
//TODO return whether already expired.
func (o *redhat) scanUnsecurePackagesUsingYumPluginSecurity() (CvePacksList, error) {
	if o.Family == "centos" {
		// CentOS has no security channel.
		// So use yum check-update && parse changelog
		return CvePacksList{}, fmt.Errorf(
			"yum updateinfo is not suppported on CentOS")
	}

	cmd := "yum --color=never repolist"
	r := o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// get advisoryID(RHSA, ALAS) - package name,version
	cmd = "yum --color=never updateinfo list available --security"
	r = o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	advIDPackNamesList, err := o.parseYumUpdateinfoListAvailable(r.Stdout)

	// get package name, version, rel to be upgrade.
	//  cmd = "yum check-update --security"
	cmd = "LANG=en_US.UTF-8 yum --color=never check-update"
	r = o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess(0, 100) {
		//returns an exit code of 100 if there are available updates.
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	updatable, err := o.parseYumCheckUpdateLines(r.Stdout)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s. err: %s", cmd, err)
	}
	o.log.Debugf("%s", pp.Sprintf("%v", updatable))

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
	cmd = "yum --color=never updateinfo --security update"
	r = o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	advisoryCveIDsList, err := o.parseYumUpdateinfo(r.Stdout)
	if err != nil {
		return CvePacksList{}, err
	}
	//  pp.Println(advisoryCveIDsList)

	// All information collected.
	// Convert to CvePacksList.
	o.log.Info("Fetching CVE details...")
	result := CvePacksList{}
	for _, advIDCveIDs := range advisoryCveIDsList {
		cveDetails, err :=
			cveapi.CveClient.FetchCveDetails(advIDCveIDs.CveIDs)
		if err != nil {
			return nil, err
		}

		for _, cveDetail := range cveDetails {
			found := false
			for i, p := range result {
				if cveDetail.CveID == p.CveID {
					advAppended := append(p.DistroAdvisories, advIDCveIDs.DistroAdvisory)
					result[i].DistroAdvisories = advAppended

					packs := dict[advIDCveIDs.DistroAdvisory.AdvisoryID]
					result[i].Packs = append(result[i].Packs, packs...)
					found = true
					break
				}
			}

			if !found {
				cpinfo := CvePacksInfo{
					CveID:            cveDetail.CveID,
					CveDetail:        cveDetail,
					DistroAdvisories: []models.DistroAdvisory{advIDCveIDs.DistroAdvisory},
					Packs:            dict[advIDCveIDs.DistroAdvisory.AdvisoryID],
				}
				result = append(result, cpinfo)
			}
		}
	}
	o.log.Info("Done")
	return result, nil
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
			switch o.Family {
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

// see test case
func (o *redhat) parseYumUpdateinfoHeaderCentOS(line string) (packs []models.PackageInfo, err error) {
	pkgs := strings.Split(strings.TrimSpace(line), ",")
	for _, pkg := range pkgs {
		packs = append(packs, models.PackageInfo{})
		s := strings.Split(pkg, "-")
		if len(s) == 3 {
			packs[len(packs)-1].Name = s[0]
			packs[len(packs)-1].Version = s[1]
			packs[len(packs)-1].Release = s[2]
		} else {
			return packs, fmt.Errorf("CentOS: Unknown Header format: %s", line)
		}
	}
	return
}

var yumHeaderPattern = regexp.MustCompile(`(ALAS-.+): (.+) priority package update for (.+)$`)

func (o *redhat) parseYumUpdateinfoHeaderAmazon(line string) (a models.DistroAdvisory, names []string, err error) {
	result := yumHeaderPattern.FindStringSubmatch(line)
	if len(result) == 4 {
		a.AdvisoryID = result[1]
		a.Severity = result[2]
		spaceSeparatedPacknames := result[3]
		names = strings.Fields(spaceSeparatedPacknames)
		return
	}
	err = fmt.Errorf("Amazon Linux: Unknown Header Format. %s", line)
	return
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
