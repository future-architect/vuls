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
		red.setDistro("fedora", "unknown")
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
			red.setDistro("oraclelinux", release)
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
	case "centos":
		cmds = []cmd{
			{"yum --changelog --assumeno update yum", []int{0, 1}},
		}

	case "rhel", "oraclelinux":
		majorVersion, err := o.Distro.MajorVersion()
		if err != nil {
			return fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
		}

		if majorVersion < 6 {
			cmds = []cmd{
				{"yum --color=never repolist", zero},
				{"yum --color=never check-update", []int{0, 100}},
				{"yum --color=never list-security --security", zero},
				{"yum --color=never info-security", zero},
			}
		} else {
			cmds = []cmd{
				{"yum --color=never repolist", zero},
				{"yum --color=never check-update", []int{0, 100}},
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

// CentOS 6, 7 	... yum-plugin-changelog
// RHEL 5     	... yum-security
// RHEL 6, 7    ... -
// Amazon 		... -
func (o *redhat) checkDependencies() error {
	var packName string
	if o.Distro.Family == "amazon" {
		return nil
	}

	majorVersion, err := o.Distro.MajorVersion()
	if err != nil {
		msg := fmt.Sprintf("Not implemented yet: %s, err: %s", o.Distro, err)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	if o.Distro.Family == "centos" {
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

	switch o.Distro.Family {
	case "centos":
		packName = "yum-plugin-changelog"
	case "rhel", "oraclelinux":
		if majorVersion < 6 {
			packName = "yum-security"
		} else {
			// yum-plugin-security is installed by default on RHEL6, 7
			return nil
		}
	default:
		return fmt.Errorf("Not implemented yet: %s", o.Distro)
	}

	cmd := "rpm -q " + packName
	if r := o.exec(cmd, noSudo); !r.isSuccess() {
		msg := fmt.Sprintf("%s is not installed", packName)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}
	o.log.Infof("Dependencies... Pass")
	return nil
}

func (o *redhat) scanPackages() error {
	var err error
	var packs []models.Package
	if packs, err = o.scanInstalledPackages(); err != nil {
		o.log.Errorf("Failed to scan installed packages")
		return err
	}
	o.setPackages(models.NewPackages(packs...))

	var vinfos models.VulnInfos
	if vinfos, err = o.scanVulnInfos(); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages")
		return err
	}
	o.setVulnInfos(vinfos)
	return nil
}

func (o *redhat) scanInstalledPackages() (installed []models.Package, err error) {
	cmd := "rpm -qa --queryformat '%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\n'"
	r := o.exec(cmd, noSudo)
	if r.isSuccess() {
		//  e.g.
		// openssl	1.0.1e	30.el6.11
		lines := strings.Split(r.Stdout, "\n")
		for _, line := range lines {
			if trimed := strings.TrimSpace(line); len(trimed) != 0 {
				var pack models.Package
				if pack, err = o.parseScannedPackagesLine(line); err != nil {
					return
				}
				installed = append(installed, pack)
			}
		}
		return
	}

	return nil, fmt.Errorf(
		"Scan packages failed. status: %d, stdout: %s, stderr: %s",
		r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *redhat) parseScannedPackagesLine(line string) (models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return models.Package{},
			fmt.Errorf("Failed to parse package line: %s", line)
	}
	ver := ""
	if fields[1] == "0" {
		ver = fields[2]
	} else {
		ver = fmt.Sprintf("%s:%s", fields[1], fields[2])
	}
	return models.Package{
		Name:    fields[0],
		Version: ver,
		Release: fields[3],
	}, nil
}

func (o *redhat) scanVulnInfos() (models.VulnInfos, error) {
	if o.Distro.Family != "centos" {
		// Amazon, RHEL, Oracle Linux has yum updateinfo as default
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

	r := o.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess(0, 100) {
		//returns an exit code of 100 if there are available updates.
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// get Updateble package name, installed, candidate version.
	packages, err := o.parseYumCheckUpdateLines(r.Stdout)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse %s. err: %s", cmd, err)
	}
	o.log.Debugf("%s", pp.Sprintf("%v", packages))

	// set candidate version info
	//TODO Mutex??
	o.Packages.MergeNewVersion(packages)

	// Collect CVE-IDs in changelog
	type PackageCveIDs struct {
		Package models.Package
		CveIDs  []string
	}

	allChangelog, err := o.getAllChangelog(packages)
	if err != nil {
		o.log.Errorf("Failed to getAllchangelog. err: %s", err)
		return nil, err
	}

	// { packageName: changelog-lines }
	var rpm2changelog map[string]*string
	rpm2changelog, err = o.divideChangelogByPackage(allChangelog)
	if err != nil {
		return nil, fmt.Errorf("Failed to parseAllChangelog. err: %s", err)
	}

	for name, clog := range rpm2changelog {
		for _, p := range o.Packages {
			n := fmt.Sprintf("%s-%s-%s", p.Name, p.NewVersion, p.NewRelease)
			if name == n {
				p.Changelog = models.Changelog{
					Contents: *clog,
					Method:   models.ChangelogExactMatchStr,
				}
				//TODO Mutex
				o.Packages[p.Name] = p
				break
			}
		}
	}

	var results []PackageCveIDs
	i := 0
	for name := range packages {
		changelog := o.getChangelogCVELines(rpm2changelog, packages[name])

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
		p := PackageCveIDs{
			Package: packages[name],
			CveIDs:  cveIDs,
		}
		results = append(results, p)

		o.log.Infof("(%d/%d) Scanned %s-%s-%s -> %s-%s : %s",
			i+1,
			len(packages),
			p.Package.Name,
			p.Package.Version,
			p.Package.Release,
			p.Package.NewVersion,
			p.Package.NewRelease,
			p.CveIDs)
		i++
	}

	// transform datastructure
	// - From
	// [
	//   {
	//     Pack:    models.Packages,
	//     CveIDs:      []string,
	//   },
	// ]
	// - To
	// map {
	//   CveID: models.Packages{}
	// }
	cveIDPackages := make(map[string]models.Packages)
	for _, res := range results {
		for _, cveID := range res.CveIDs {
			if packages, ok := cveIDPackages[cveID]; ok {
				packages[res.Package.Name] = res.Package
				cveIDPackages[cveID] = packages
			} else {
				cveIDPackages[cveID] = models.NewPackages(res.Package)
			}
		}
	}

	vinfos := models.VulnInfos{}
	for cveID, packs := range cveIDPackages {
		names := []string{}
		for name := range packs {
			names = append(names, name)
		}

		// Amazon, RHEL do not use this method, so VendorAdvisory do not set.
		vinfos[cveID] = models.VulnInfo{
			CveID:        cveID,
			PackageNames: names,
			Confidence:   models.ChangelogExactMatch,
		}
	}
	return vinfos, nil
}

// parseYumCheckUpdateLines parse yum check-update to get package name, candidate version
func (o *redhat) parseYumCheckUpdateLines(stdout string) (models.Packages, error) {
	results := models.Packages{}
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

			installed, found := o.Packages[candidate.Name]
			if !found {
				o.log.Warnf("Not found the package in rpm -qa. candidate: %s-%s-%s",
					candidate.Name, candidate.Version, candidate.Release)
				results[candidate.Name] = candidate
				continue
			}
			installed.NewVersion = candidate.NewVersion
			installed.NewRelease = candidate.NewRelease
			installed.Repository = candidate.Repository
			results[installed.Name] = installed
		}
	}
	return results, nil
}

func (o *redhat) parseYumCheckUpdateLine(line string) (models.Package, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return models.Package{}, fmt.Errorf("Unknown format: %s", line)
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
		return models.Package{}, fmt.Errorf("Unknown format: %s", line)
	}
	release := verfields[1]
	repos := strings.Join(fields[2:len(fields)], " ")

	return models.Package{
		Name:       packName,
		NewVersion: verfields[0],
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

func (o *redhat) getChangelogCVELines(rpm2changelog map[string]*string, pack models.Package) string {
	rpm := fmt.Sprintf("%s-%s-%s", pack.Name, pack.NewVersion, pack.NewRelease)
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

func (o *redhat) divideChangelogByPackage(allChangelog string) (map[string]*string, error) {
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
				rpm = o.regexpReplace(rpm, `\.(i386|i486|i586|i686|k6|athlon|x86_64|noarch|ppc|alpha|sparc)$`, "")
				if ss := strings.Split(rpm, ":"); 1 < len(ss) {
					epoch := ss[0]
					packVersion := strings.Join(ss[1:len(ss)], ":")
					if sss := strings.Split(packVersion, "-"); 2 < len(sss) {
						version := strings.Join(sss[len(sss)-2:len(sss)], "-")
						name := strings.Join(sss[0:len(sss)-2], "-")
						rpm = fmt.Sprintf("%s-%s:%s", name, epoch, version)
					}
				}

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
func (o *redhat) getAllChangelog(packages models.Packages) (stdout string, err error) {
	packageNames := ""
	for _, pack := range packages {
		packageNames += fmt.Sprintf("%s ", pack.Name)
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

	// yum update --changelog doesn't have --color option.
	command += fmt.Sprintf(" LANGUAGE=en_US.UTF-8 yum --changelog --assumeno update %s ", yumopts) + packageNames

	r := o.exec(command, sudo)
	if !r.isSuccess(0, 1) {
		return "", fmt.Errorf(
			"Failed to get changelog. status: %d, stdout: %s, stderr: %s",
			r.ExitStatus, r.Stdout, r.Stderr)
	}
	return strings.Replace(r.Stdout, "\r", "", -1), nil
}

type distroAdvisoryCveIDs struct {
	DistroAdvisory models.DistroAdvisory
	CveIDs         []string
}

// Scaning unsecure packages using yum-plugin-security.
// Amazon, RHEL, Oracle Linux
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

	// get advisoryID(RHSA, ALAS, ELSA) - package name,version
	major, err := (o.Distro.MajorVersion())
	if err != nil {
		return nil, fmt.Errorf("Not implemented yet: %s, err: %s", o.Distro, err)
	}

	if (o.Distro.Family == "rhel" || o.Distro.Family == "oraclelinux") && major == 5 {
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
	if (o.Distro.Family == "rhel" || o.Distro.Family == "oraclelinux") && major == 5 {
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
	//  pp.Println(advisoryCveIDsList)

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
				//TODO remove
				//  sort.Strings(foundCveIDs)

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
			case "rhel", "amazon", "oraclelinux":
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
	case "amazon":
		return false
	default:
		return true
	}
}
