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
	linux
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

	// set sudo option flag
	c.SudoOpt = config.SudoOption{ExecBySudoSh: true}
	red.setServerInfo(c)

	if r := sshExec(c, "ls /etc/fedora-release", noSudo); r.isSuccess() {
		red.setDistributionInfo("fedora", "unknown")
		Log.Warn("Fedora not tested yet. Host: %s:%s", c.Host, c.Port)
		return true, red
	}

	if r := sshExec(c, "ls /etc/redhat-release", noSudo); r.isSuccess() {
		// https://www.rackaid.com/blog/how-to-determine-centos-or-red-hat-version/
		// e.g.
		// $ cat /etc/redhat-release
		// CentOS release 6.5 (Final)
		if r := sshExec(c, "cat /etc/redhat-release", noSudo); r.isSuccess() {
			re, _ := regexp.Compile(`(.*) release (\d[\d.]*)`)
			result := re.FindStringSubmatch(strings.TrimSpace(r.Stdout))
			if len(result) != 3 {
				Log.Warn(
					"Failed to parse RedHat/CentOS version. stdout: %s, Host: %s:%s",
					r.Stdout, c.Host, c.Port)
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

	Log.Debugf("Not RedHat like Linux. Host: %s:%s", c.Host, c.Port)
	return false, red
}

// CentOS 5 ... yum-plugin-security, yum-changelog
// CentOS 6 ... yum-plugin-security, yum-plugin-changelog
// CentOS 7 ... yum-plugin-security, yum-plugin-changelog
// RHEL, Amazon ... no additinal packages needed
func (o *redhat) install() error {

	switch o.Family {
	case "rhel", "amazon":
		o.log.Infof("Nothing to do")
		return nil
	}

	if err := o.installYumPluginSecurity(); err != nil {
		return err
	}
	return o.installYumChangelog()
}

func (o *redhat) installYumPluginSecurity() error {

	if r := o.ssh("rpm -q yum-plugin-security", noSudo); r.isSuccess() {
		o.log.Infof("Ignored: yum-plugin-security already installed")
		return nil
	}

	cmd := util.PrependProxyEnv("yum install -y yum-plugin-security")
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		return fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
	}
	return nil
}

func (o *redhat) installYumChangelog() error {
	o.log.Info("Installing yum-plugin-security...")

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
			o.log.Infof("Ignored: %s already installed.", packName)
			return nil
		}

		cmd = util.PrependProxyEnv("yum install -y " + packName)
		if r := o.ssh(cmd, sudo); !r.isSuccess() {
			return fmt.Errorf(
				"Failed to install %s. status: %d, stdout: %s, stderr: %s",
				packName, r.ExitStatus, r.Stdout, r.Stderr)
		}
		o.log.Infof("Installed: %s.", packName)
	}
	return nil
}

func (o *redhat) checkRequiredPackagesInstalled() error {
	if config.Conf.UseYumPluginSecurity {
		// check if yum-plugin-security is installed.
		// Amazon Linux, REHL can execute 'yum updateinfo --security updates' without yum-plugin-security
		cmd := "rpm -q yum-plugin-security"
		if o.Family == "centos" {
			if r := o.ssh(cmd, noSudo); !r.isSuccess() {
				msg := "yum-plugin-security is not installed"
				o.log.Errorf(msg)
				return fmt.Errorf(msg)
			}
		}
		return nil
	}

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
		o.log.Errorf("Failed to scan valnerable packages")
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
				if packinfo, err = o.parseScanedPackagesLine(line); err != nil {
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

func (o *redhat) parseScanedPackagesLine(line string) (pack models.PackageInfo, err error) {
	re, _ := regexp.Compile(`^([^\t']+)\t([^\t]+)\t(.+)$`)
	result := re.FindStringSubmatch(line)
	if len(result) == 4 {
		pack.Name = result[1]
		pack.Version = result[2]
		pack.Release = strings.TrimSpace(result[3])
	} else {
		err = fmt.Errorf("redhat: Failed to parse package line: %s", line)
	}
	return
}

func (o *redhat) scanUnsecurePackages() ([]CvePacksInfo, error) {
	if o.Family != "centos" || config.Conf.UseYumPluginSecurity {
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

	cmd := "yum check-update"
	r := o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess(0, 100) {
		//returns an exit code of 100 if there are available updates.
		return nil, fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
	}

	// get Updateble package name, installed, candidate version.
	packInfoList, err := o.parseYumCheckUpdateLines(r.Stdout)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s. err: %s", cmd, err)
	}
	o.log.Debugf("%s", pp.Sprintf("%s", packInfoList))

	// Collect CVE-IDs in changelog
	type PackInfoCveIDs struct {
		PackInfo models.PackageInfo
		CveIDs   []string
	}
	var results []PackInfoCveIDs
	for i, packInfo := range packInfoList {
		changelog, err := o.getChangelog(packInfo.Name)
		if err != nil {
			o.log.Errorf("Failed to collect CVE. err: %s", err)
			return nil, err
		}

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
	sort.Sort(CvePacksList(cvePacksList))
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
			candidate, err := o.parseYumCheckUpdateLine(line)
			if err != nil {
				return models.PackageInfoList{}, err
			}

			installed, found := o.Packages.FindByName(candidate.Name)
			if !found {
				return models.PackageInfoList{}, fmt.Errorf(
					"Failed to parse yum check update line: %s-%s-%s",
					candidate.Name, candidate.Version, candidate.Release)
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
	version := fields[0]
	release := fields[1]
	return models.PackageInfo{
		Name:       packName,
		NewVersion: version,
		NewRelease: release,
	}, nil
}

func (o *redhat) getChangelog(packageNames string) (stdout string, err error) {
	command := "echo N | "
	if 0 < len(config.Conf.HTTPProxy) {
		command += util.ProxyEnv()
	}
	command += fmt.Sprintf(" yum update --changelog %s | grep CVE", packageNames)

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

	cmd := "yum repolist"
	r := o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
	}

	// get advisoryID(RHSA, ALAS) - package name,version
	cmd = "yum updateinfo list available --security"
	r = o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
	}
	advIDPackNamesList, err := o.parseYumUpdateinfoListAvailable(r.Stdout)

	// get package name, version, rel to be upgrade.
	cmd = "yum check-update --security"
	r = o.ssh(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess(0, 100) {
		//returns an exit code of 100 if there are available updates.
		return nil, fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
	}
	vulnerablePackInfoList, err := o.parseYumCheckUpdateLines(r.Stdout)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s. err: %s", cmd, err)
	}
	o.log.Debugf("%s", pp.Sprintf("%s", vulnerablePackInfoList))
	for i, packInfo := range vulnerablePackInfoList {
		installedPack, found := o.Packages.FindByName(packInfo.Name)
		if !found {
			return nil, fmt.Errorf(
				"Parsed package not found. packInfo: %#v", packInfo)
		}
		vulnerablePackInfoList[i].Version = installedPack.Version
		vulnerablePackInfoList[i].Release = installedPack.Release
	}

	dict := map[string][]models.PackageInfo{}
	for _, advIDPackNames := range advIDPackNamesList {
		packInfoList := models.PackageInfoList{}
		for _, packName := range advIDPackNames.PackNames {
			packInfo, found := vulnerablePackInfoList.FindByName(packName)
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
	cmd = "yum updateinfo --security update"
	r = o.ssh(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
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
		if match, _ := o.isHorizontalRule(line); match {

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

func (o *redhat) isHorizontalRule(line string) (bool, error) {
	return regexp.MatchString("^=+$", line)
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

func (o *redhat) parseYumUpdateinfoHeaderAmazon(line string) (a models.DistroAdvisory, names []string, err error) {
	re, _ := regexp.Compile(`(ALAS-.+): (.+) priority package update for (.+)$`)
	result := re.FindStringSubmatch(line)
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

func (o *redhat) parseYumUpdateinfoLineToGetCveIDs(line string) []string {
	re, _ := regexp.Compile(`(CVE-\d{4}-\d{4})`)
	return re.FindAllString(line, -1)
}

func (o *redhat) parseYumUpdateinfoToGetAdvisoryID(line string) (advisoryID string, found bool) {
	re, _ := regexp.Compile(`^ *Update ID : (.*)$`)
	result := re.FindStringSubmatch(line)
	if len(result) != 2 {
		return "", false
	}
	return strings.TrimSpace(result[1]), true
}

func (o *redhat) parseYumUpdateinfoLineToGetIssued(line string) (date time.Time, found bool) {
	return o.parseYumUpdateinfoLineToGetDate(line, `^\s*Issued : (\d{4}-\d{2}-\d{2})`)
}

func (o *redhat) parseYumUpdateinfoLineToGetUpdated(line string) (date time.Time, found bool) {
	return o.parseYumUpdateinfoLineToGetDate(line, `^\s*Updated : (\d{4}-\d{2}-\d{2})`)
}

func (o *redhat) parseYumUpdateinfoLineToGetDate(line, regexpFormat string) (date time.Time, found bool) {
	re, _ := regexp.Compile(regexpFormat)
	result := re.FindStringSubmatch(line)
	if len(result) != 2 {
		return date, false
	}
	t, err := time.Parse("2006-01-02", result[1])
	if err != nil {
		return date, false
	}
	return t, true
}

func (o *redhat) isDescriptionLine(line string) bool {
	re, _ := regexp.Compile(`^\s*Description : `)
	return re.MatchString(line)
}

func (o *redhat) parseYumUpdateinfoToGetSeverity(line string) (severity string, found bool) {
	re, _ := regexp.Compile(`^ *Severity : (.*)$`)
	result := re.FindStringSubmatch(line)
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
