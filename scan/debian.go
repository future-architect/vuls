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
)

// inherit OsTypeInterface
type debian struct {
	linux
}

// NewDebian is constructor
func newDebian(c config.ServerInfo) *debian {
	d := &debian{}
	d.log = util.NewCustomLogger(c)
	return d
}

// Ubuntu, Debian
// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/debian.rb
func detectDebian(c config.ServerInfo) (itsMe bool, deb osTypeInterface) {

	deb = newDebian(c)

	// set sudo option flag
	c.SudoOpt = config.SudoOption{ExecBySudo: true}
	deb.setServerInfo(c)

	if r := sshExec(c, "ls /etc/debian_version", noSudo); !r.isSuccess() {
		Log.Debugf("Not Debian like Linux. Host: %s:%s", c.Host, c.Port)
		return false, deb
	}

	if r := sshExec(c, "lsb_release -ir", noSudo); r.isSuccess() {
		//  e.g.
		//  root@fa3ec524be43:/# lsb_release -ir
		//  Distributor ID:	Ubuntu
		//  Release:	14.04
		re, _ := regexp.Compile(
			`(?s)^Distributor ID:\s*(.+?)\n*Release:\s*(.+?)$`)
		result := re.FindStringSubmatch(trim(r.Stdout))

		if len(result) == 0 {
			deb.setDistributionInfo("debian/ubuntu", "unknown")
			Log.Warnf(
				"Unknown Debian/Ubuntu version. lsb_release -ir: %s, Host: %s:%s",
				r.Stdout, c.Host, c.Port)
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistributionInfo(distro, trim(result[2]))
		}
		return true, deb
	}

	if r := sshExec(c, "cat /etc/lsb-release", noSudo); r.isSuccess() {
		//  e.g.
		//  DISTRIB_ID=Ubuntu
		//  DISTRIB_RELEASE=14.04
		//  DISTRIB_CODENAME=trusty
		//  DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
		re, _ := regexp.Compile(
			`(?s)^DISTRIB_ID=(.+?)\n*DISTRIB_RELEASE=(.+?)\n.*$`)
		result := re.FindStringSubmatch(trim(r.Stdout))
		if len(result) == 0 {
			Log.Warnf(
				"Unknown Debian/Ubuntu. cat /etc/lsb-release: %s, Host: %s:%s",
				r.Stdout, c.Host, c.Port)
			deb.setDistributionInfo("debian/ubuntu", "unknown")
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistributionInfo(distro, trim(result[2]))
		}
		return true, deb
	}

	// Debian
	cmd := "cat /etc/debian_version"
	if r := sshExec(c, cmd, noSudo); r.isSuccess() {
		deb.setDistributionInfo("debian", trim(r.Stdout))
		return true, deb
	}

	Log.Debugf("Not Debian like Linux. Host: %s:%s", c.Host, c.Port)
	return false, deb
}

func trim(str string) string {
	return strings.TrimSpace(str)
}

func (o *debian) install() error {

	// apt-get update
	o.log.Infof("apt-get update...")
	cmd := util.PrependProxyEnv("apt-get update")
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		msg := fmt.Sprintf("Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	if o.Family == "debian" {
		// install aptitude
		cmd = util.PrependProxyEnv("apt-get install --force-yes -y aptitude")
		if r := o.ssh(cmd, sudo); !r.isSuccess() {
			msg := fmt.Sprintf("Failed to %s. status: %d, stdout: %s, stderr: %s",
				cmd, r.ExitStatus, r.Stdout, r.Stderr)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		o.log.Infof("Installed: aptitude")
	}

	// install unattended-upgrades
	if !config.Conf.UseUnattendedUpgrades {
		return nil
	}

	if r := o.ssh("type unattended-upgrade", noSudo); r.isSuccess() {
		o.log.Infof(
			"Ignored: unattended-upgrade already installed")
		return nil
	}

	cmd = util.PrependProxyEnv(
		"apt-get install --force-yes -y unattended-upgrades")
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		msg := fmt.Sprintf("Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	o.log.Infof("Installed: unattended-upgrades")
	return nil
}

func (o *debian) scanPackages() error {
	var err error
	var packs []models.PackageInfo
	if packs, err = o.scanInstalledPackages(); err != nil {
		o.log.Errorf("Failed to scan installed packages")
		return err
	}
	o.setPackages(packs)

	var unsecurePacks []CvePacksInfo
	if unsecurePacks, err = o.scanUnsecurePackages(packs); err != nil {
		o.log.Errorf("Failed to scan valnerable packages")
		return err
	}
	o.setUnsecurePackages(unsecurePacks)
	return nil
}

func (o *debian) scanInstalledPackages() (packs []models.PackageInfo, err error) {
	r := o.ssh("dpkg-query -W", noSudo)
	if !r.isSuccess() {
		return packs, fmt.Errorf(
			"Failed to scan packages. status: %d, stdout:%s, stderr: %s",
			r.ExitStatus, r.Stdout, r.Stderr)
	}

	//  e.g.
	//  curl	7.19.7-40.el6_6.4
	//  openldap	2.4.39-8.el6
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); len(trimmed) != 0 {
			name, version, err := o.parseScanedPackagesLine(trimmed)
			if err != nil {
				return nil, fmt.Errorf(
					"Debian: Failed to parse package line: %s", line)
			}
			packs = append(packs, models.PackageInfo{
				Name:    name,
				Version: version,
			})
		}
	}
	return
}

func (o *debian) parseScanedPackagesLine(line string) (name, version string, err error) {
	re, _ := regexp.Compile(`^([^\t']+)\t(.+)$`)
	result := re.FindStringSubmatch(line)
	if len(result) == 3 {
		// remove :amd64, i386...
		name = regexp.MustCompile(":.+").ReplaceAllString(result[1], "")
		version = result[2]
		return
	}

	return "", "", fmt.Errorf("Unknown format: %s", line)
}

//  unattended-upgrade command need to check security upgrades).
func (o *debian) checkRequiredPackagesInstalled() error {

	if o.Family == "debian" {
		if r := o.ssh("test -f /usr/bin/aptitude", sudo); !r.isSuccess() {
			msg := "aptitude is not installed"
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}

	if !config.Conf.UseUnattendedUpgrades {
		return nil
	}

	if r := o.ssh("type unattended-upgrade", noSudo); !r.isSuccess() {
		msg := "unattended-upgrade is not installed"
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}
	return nil
}

//TODO return whether already expired.
func (o *debian) scanUnsecurePackages(packs []models.PackageInfo) ([]CvePacksInfo, error) {
	//  cmd := prependProxyEnv(conf.HTTPProxy, "apt-get update | cat; echo 1")
	cmd := util.PrependProxyEnv("apt-get update")
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		return nil, fmt.Errorf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr,
		)
	}

	var upgradablePackNames []string
	var err error
	if config.Conf.UseUnattendedUpgrades {
		upgradablePackNames, err = o.GetUnsecurePackNamesUsingUnattendedUpgrades()
		if err != nil {
			return []CvePacksInfo{}, err
		}
	} else {
		upgradablePackNames, err = o.GetUpgradablePackNames()
		if err != nil {
			return []CvePacksInfo{}, err
		}
	}

	// Convert package name to PackageInfo struct
	var unsecurePacks []models.PackageInfo
	for _, name := range upgradablePackNames {
		for _, pack := range packs {
			if pack.Name == name {
				unsecurePacks = append(unsecurePacks, pack)
				break
			}
		}
	}

	unsecurePacks, err = o.fillCandidateVersion(unsecurePacks)
	if err != nil {
		return nil, err
	}

	// Collect CVE information of upgradable packages
	cvePacksInfos, err := o.scanPackageCveInfos(unsecurePacks)
	if err != nil {
		return nil, fmt.Errorf("Failed to scan unsecure packages. err: %s", err)
	}

	return cvePacksInfos, nil
}

func (o *debian) fillCandidateVersion(packs []models.PackageInfo) ([]models.PackageInfo, error) {
	reqChan := make(chan models.PackageInfo, len(packs))
	resChan := make(chan models.PackageInfo, len(packs))
	errChan := make(chan error, len(packs))
	defer close(resChan)
	defer close(errChan)
	defer close(reqChan)

	go func() {
		for _, pack := range packs {
			reqChan <- pack
		}
	}()

	timeout := time.After(5 * 60 * time.Second)
	concurrency := 5
	tasks := util.GenWorkers(concurrency)
	for range packs {
		tasks <- func() {
			select {
			case pack := <-reqChan:
				func(p models.PackageInfo) {
					cmd := fmt.Sprintf("apt-cache policy %s", p.Name)
					r := o.ssh(cmd, sudo)
					if !r.isSuccess() {
						errChan <- fmt.Errorf(
							"Failed to %s. status: %d, stdout: %s, stderr: %s",
							cmd, r.ExitStatus, r.Stdout, r.Stderr)
						return
					}
					ver, err := o.parseAptCachePolicy(r.Stdout, p.Name)
					if err != nil {
						errChan <- fmt.Errorf("Failed to parse %s", err)
					}
					p.NewVersion = ver.Candidate
					resChan <- p
				}(pack)
			}
		}
	}

	result := []models.PackageInfo{}
	for i := 0; i < len(packs); i++ {
		select {
		case pack := <-resChan:
			result = append(result, pack)
			o.log.Infof("(%d/%d) Upgradable: %s-%s -> %s",
				i+1, len(packs), pack.Name, pack.Version, pack.NewVersion)
		case err := <-errChan:
			return nil, err
		case <-timeout:
			return nil, fmt.Errorf("Timeout fillCandidateVersion.")
		}
	}
	return result, nil
}

func (o *debian) GetUnsecurePackNamesUsingUnattendedUpgrades() (packNames []string, err error) {
	cmd := util.PrependProxyEnv("unattended-upgrades --dry-run -d 2>&1 ")
	release, err := strconv.ParseFloat(o.Release, 64)
	if err != nil {
		return packNames, fmt.Errorf(
			"OS Release Version is invalid, %s, %s", o.Family, o.Release)
	}
	switch {
	case release < 12:
		return packNames, fmt.Errorf(
			"Support expired. %s, %s", o.Family, o.Release)

	case 12 < release && release < 14:
		cmd += `| grep 'pkgs that look like they should be upgraded:' |
			sed -e 's/pkgs that look like they should be upgraded://g'`

	case 14 < release:
		cmd += `| grep 'Packages that will be upgraded:' |
			sed -e 's/Packages that will be upgraded://g'`

	default:
		return packNames, fmt.Errorf(
			"Not supported yet. %s, %s", o.Family, o.Release)
	}

	r := o.ssh(cmd, sudo)
	if r.isSuccess(0, 1) {
		packNames = strings.Split(strings.TrimSpace(r.Stdout), " ")
		return packNames, nil
	}

	return packNames, fmt.Errorf(
		"Failed to %s. status: %d, stdout: %s, stderr: %s",
		cmd, r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *debian) GetUpgradablePackNames() (packNames []string, err error) {
	cmd := util.PrependProxyEnv("apt-get upgrade --dry-run")
	r := o.ssh(cmd, sudo)
	if r.isSuccess(0, 1) {
		return o.parseAptGetUpgrade(r.Stdout)
	}
	return packNames, fmt.Errorf(
		"Failed to %s. status: %d, stdout: %s, stderr: %s",
		cmd, r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *debian) parseAptGetUpgrade(stdout string) (upgradableNames []string, err error) {
	startRe, _ := regexp.Compile(`The following packages will be upgraded:`)
	stopRe, _ := regexp.Compile(`^(\d+) upgraded.*`)
	startLineFound, stopLineFound := false, false

	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		if !startLineFound {
			if matche := startRe.MatchString(line); matche {
				startLineFound = true
			}
			continue
		}
		result := stopRe.FindStringSubmatch(line)
		if len(result) == 2 {
			numUpgradablePacks, err := strconv.Atoi(result[1])
			if err != nil {
				return nil, fmt.Errorf(
					"Failed to scan upgradable packages number. line: %s", line)
			}
			if numUpgradablePacks != len(upgradableNames) {
				return nil, fmt.Errorf(
					"Failed to scan upgradable packages, expected: %s, detected: %d",
					result[1], len(upgradableNames))
			}
			stopLineFound = true
			o.log.Debugf("Found the stop line. line: %s", line)
			break
		}
		upgradableNames = append(upgradableNames, strings.Fields(line)...)
	}
	if !startLineFound {
		// no upgrades
		return
	}
	if !stopLineFound {
		// There are upgrades, but not found the stop line.
		return nil, fmt.Errorf("Failed to scan upgradable packages")
	}
	return
}

func (o *debian) scanPackageCveInfos(unsecurePacks []models.PackageInfo) (cvePacksList CvePacksList, err error) {

	// { CVE ID: [packageInfo] }
	cvePackages := make(map[string][]models.PackageInfo)

	type strarray []string
	resChan := make(chan struct {
		models.PackageInfo
		strarray
	}, len(unsecurePacks))
	errChan := make(chan error, len(unsecurePacks))
	reqChan := make(chan models.PackageInfo, len(unsecurePacks))
	defer close(resChan)
	defer close(errChan)
	defer close(reqChan)

	go func() {
		for _, pack := range unsecurePacks {
			reqChan <- pack
		}
	}()

	timeout := time.After(30 * 60 * time.Second)

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range unsecurePacks {
		tasks <- func() {
			select {
			case pack := <-reqChan:
				func(p models.PackageInfo) {
					if cveIds, err := o.scanPackageCveIds(p); err != nil {
						errChan <- err
					} else {
						resChan <- struct {
							models.PackageInfo
							strarray
						}{p, cveIds}
					}
				}(pack)
			}
		}
	}

	for i := 0; i < len(unsecurePacks); i++ {
		select {
		case pair := <-resChan:
			pack := pair.PackageInfo
			cveIds := pair.strarray
			for _, cveID := range cveIds {
				cvePackages[cveID] = appendPackIfMissing(cvePackages[cveID], pack)
			}
			o.log.Infof("(%d/%d) Scanned %s-%s : %s",
				i+1, len(unsecurePacks), pair.Name, pair.PackageInfo.Version, cveIds)
		case err := <-errChan:
			if err != nil {
				return nil, err
			}
		case <-timeout:
			return nil, fmt.Errorf("Timeout scanPackageCveIds.")
		}
	}

	var cveIds []string
	for k := range cvePackages {
		cveIds = append(cveIds, k)
	}

	o.log.Debugf("%d Cves are found. cves: %v", len(cveIds), cveIds)

	o.log.Info("Fetching CVE details...")
	cveDetails, err := cveapi.CveClient.FetchCveDetails(cveIds)
	if err != nil {
		return nil, err
	}
	o.log.Info("Done")

	for _, detail := range cveDetails {
		cvePacksList = append(cvePacksList, CvePacksInfo{
			CveID:     detail.CveID,
			CveDetail: detail,
			Packs:     cvePackages[detail.CveID],
			//  CvssScore: cinfo.CvssScore(conf.Lang),
		})
	}
	sort.Sort(CvePacksList(cvePacksList))
	return
}

func (o *debian) scanPackageCveIds(pack models.PackageInfo) (cveIds []string, err error) {
	cmd := ""
	switch o.Family {
	case "ubuntu":
		cmd = fmt.Sprintf(`apt-get changelog %s | grep '\(urgency\|CVE\)'`, pack.Name)
	case "debian":
		cmd = fmt.Sprintf(`aptitude changelog %s | grep '\(urgency\|CVE\)'`, pack.Name)
	}
	cmd = util.PrependProxyEnv(cmd)

	r := o.ssh(cmd, noSudo)
	if !r.isSuccess() {
		o.log.Warnf(
			"Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
		// Ignore this Error.
		return nil, nil

	}
	cveIds, err = o.getCveIDParsingChangelog(r.Stdout, pack.Name, pack.Version)
	if err != nil {
		trimUbuntu := strings.Split(pack.Version, "ubuntu")[0]
		return o.getCveIDParsingChangelog(r.Stdout, pack.Name, trimUbuntu)
	}
	return
}

func (o *debian) getCveIDParsingChangelog(changelog string,
	packName string, versionOrLater string) (cveIDs []string, err error) {

	cveIDs, err = o.parseChangelog(changelog, packName, versionOrLater)
	if err == nil {
		return
	}

	ver := strings.Split(versionOrLater, "ubuntu")[0]
	cveIDs, err = o.parseChangelog(changelog, packName, ver)
	if err == nil {
		return
	}

	splittedByColon := strings.Split(versionOrLater, ":")
	if 1 < len(splittedByColon) {
		ver = splittedByColon[1]
	}
	cveIDs, err = o.parseChangelog(changelog, packName, ver)
	if err == nil {
		return
	}

	//TODO report as unable to parse changelog.
	o.log.Warn(err)
	return []string{}, nil
}

// Collect CVE-IDs included in the changelog.
// The version which specified in argument(versionOrLater) is excluded.
func (o *debian) parseChangelog(changelog string,
	packName string, versionOrLater string) (cveIDs []string, err error) {

	cveRe, _ := regexp.Compile(`(CVE-\d{4}-\d{4})`)
	stopRe, _ := regexp.Compile(fmt.Sprintf(`\(%s\)`, regexp.QuoteMeta(versionOrLater)))
	stopLineFound := false
	lines := strings.Split(changelog, "\n")
	for _, line := range lines {
		if matche := stopRe.MatchString(line); matche {
			o.log.Debugf("Found the stop line. line: %s", line)
			stopLineFound = true
			break
		} else if matches := cveRe.FindAllString(line, -1); len(matches) > 0 {
			for _, m := range matches {
				cveIDs = util.AppendIfMissing(cveIDs, m)
			}
		}
	}
	if !stopLineFound {
		return []string{}, fmt.Errorf(
			"Failed to scan CVE IDs. The version is not in changelog. name: %s, version: %s",
			packName,
			versionOrLater,
		)
	}
	return
}

type packCandidateVer struct {
	Name      string
	Installed string
	Candidate string
}

// parseAptCachePolicy the stdout of parse pat-get cache policy
func (o *debian) parseAptCachePolicy(stdout, name string) (packCandidateVer, error) {
	ver := packCandidateVer{Name: name}
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "Installed:":
			ver.Installed = fields[1]
		case "Candidate:":
			ver.Candidate = fields[1]
			return ver, nil
		default:
			// nop
		}
	}
	return ver, fmt.Errorf("Unknown Format: %s", stdout)
}

func appendPackIfMissing(slice []models.PackageInfo, s models.PackageInfo) []models.PackageInfo {
	for _, ele := range slice {
		if ele.Name == s.Name &&
			ele.Version == s.Version &&
			ele.Release == s.Release {
			return slice
		}
	}
	return append(slice, s)
}
