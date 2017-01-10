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
	"strconv"
	"strings"
	"time"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type debian struct {
	base
}

// NewDebian is constructor
func newDebian(c config.ServerInfo) *debian {
	d := &debian{}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

// Ubuntu, Debian
// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/debian.rb
func detectDebian(c config.ServerInfo) (itsMe bool, deb osTypeInterface, err error) {
	deb = newDebian(c)

	if r := sshExec(c, "ls /etc/debian_version", noSudo); !r.isSuccess() {
		if r.Error != nil {
			return false, deb, r.Error
		}
		if r.ExitStatus == 255 {
			return false, deb, fmt.Errorf(
				"Unable to connect via SSH. Check SSH settings. %s", r)
		}
		Log.Debugf("Not Debian like Linux. %s", r)
		return false, deb, nil
	}

	if r := sshExec(c, "lsb_release -ir", noSudo); r.isSuccess() {
		//  e.g.
		//  root@fa3ec524be43:/# lsb_release -ir
		//  Distributor ID:	Ubuntu
		//  Release:	14.04
		re := regexp.MustCompile(`(?s)^Distributor ID:\s*(.+?)\n*Release:\s*(.+?)$`)
		result := re.FindStringSubmatch(trim(r.Stdout))

		if len(result) == 0 {
			deb.setDistro("debian/ubuntu", "unknown")
			Log.Warnf(
				"Unknown Debian/Ubuntu version. lsb_release -ir: %s", r)
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistro(distro, trim(result[2]))
		}
		return true, deb, nil
	}

	if r := sshExec(c, "cat /etc/lsb-release", noSudo); r.isSuccess() {
		//  e.g.
		//  DISTRIB_ID=Ubuntu
		//  DISTRIB_RELEASE=14.04
		//  DISTRIB_CODENAME=trusty
		//  DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
		re := regexp.MustCompile(`(?s)^DISTRIB_ID=(.+?)\n*DISTRIB_RELEASE=(.+?)\n.*$`)
		result := re.FindStringSubmatch(trim(r.Stdout))
		if len(result) == 0 {
			Log.Warnf(
				"Unknown Debian/Ubuntu. cat /etc/lsb-release: %s", r)
			deb.setDistro("debian/ubuntu", "unknown")
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistro(distro, trim(result[2]))
		}
		return true, deb, nil
	}

	// Debian
	cmd := "cat /etc/debian_version"
	if r := sshExec(c, cmd, noSudo); r.isSuccess() {
		deb.setDistro("debian", trim(r.Stdout))
		return true, deb, nil
	}

	Log.Debugf("Not Debian like Linux: %s", c.ServerName)
	return false, deb, nil
}

func trim(str string) string {
	return strings.TrimSpace(str)
}

func (o *debian) checkIfSudoNoPasswd() error {
	r := o.ssh("apt-get -v", sudo)
	if !r.isSuccess() {
		o.log.Errorf("sudo error on %s", r)
		return fmt.Errorf("Failed to sudo: %s", r)
	}
	o.log.Infof("sudo ... OK")
	return nil
}

func (o *debian) checkDependencies() error {
	switch o.Distro.Family {
	case "ubuntu":
		return nil

	case "debian":
		// Debian needs aptitude to get changelogs.
		// Because unable to get changelogs via apt-get changelog on Debian.
		name := "aptitude"
		cmd := name + " -h"
		if r := o.ssh(cmd, noSudo); !r.isSuccess() {
			o.lackDependencies = []string{name}
		}
		return nil

	default:
		return fmt.Errorf("Not implemented yet: %s", o.Distro)
	}
}

func (o *debian) install() error {
	if len(o.lackDependencies) == 0 {
		return nil
	}

	// apt-get update
	o.log.Infof("apt-get update...")
	cmd := util.PrependProxyEnv("apt-get update")
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		msg := fmt.Sprintf("Failed to SSH: %s", r)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}

	for _, name := range o.lackDependencies {
		cmd = util.PrependProxyEnv("apt-get install -y " + name)
		if r := o.ssh(cmd, sudo); !r.isSuccess() {
			msg := fmt.Sprintf("Failed to SSH: %s", r)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		o.log.Infof("Installed: " + name)
	}
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

	var unsecurePacks []models.VulnInfo
	if unsecurePacks, err = o.scanUnsecurePackages(packs); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages")
		return err
	}
	o.setVulnInfos(unsecurePacks)
	return nil
}

func (o *debian) scanInstalledPackages() (packs []models.PackageInfo, err error) {
	r := o.ssh("dpkg-query -W", noSudo)
	if !r.isSuccess() {
		return packs, fmt.Errorf("Failed to SSH: %s", r)
	}

	//  e.g.
	//  curl	7.19.7-40.el6_6.4
	//  openldap	2.4.39-8.el6
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); len(trimmed) != 0 {
			name, version, err := o.parseScannedPackagesLine(trimmed)
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

var packageLinePattern = regexp.MustCompile(`^([^\t']+)\t(.+)$`)

func (o *debian) parseScannedPackagesLine(line string) (name, version string, err error) {
	result := packageLinePattern.FindStringSubmatch(line)
	if len(result) == 3 {
		// remove :amd64, i386...
		name = result[1]
		if i := strings.IndexRune(name, ':'); i >= 0 {
			name = name[:i]
		}
		version = result[2]
		return
	}

	return "", "", fmt.Errorf("Unknown format: %s", line)
}

func (o *debian) checkRequiredPackagesInstalled() error {
	if o.Distro.Family == "debian" {
		if r := o.ssh("test -f /usr/bin/aptitude", noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("aptitude is not installed: %s", r)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}
	return nil
}

func (o *debian) scanUnsecurePackages(installed []models.PackageInfo) ([]models.VulnInfo, error) {
	o.log.Infof("apt-get update...")
	cmd := util.PrependProxyEnv("apt-get update")
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	// Convert the name of upgradable packages to PackageInfo struct
	upgradableNames, err := o.GetUpgradablePackNames()
	if err != nil {
		return nil, err
	}
	var upgradablePacks []models.PackageInfo
	for _, name := range upgradableNames {
		for _, pack := range installed {
			if pack.Name == name {
				upgradablePacks = append(upgradablePacks, pack)
				break
			}
		}
	}

	// Fill the candidate versions of upgradable packages
	upgradablePacks, err = o.fillCandidateVersion(upgradablePacks)
	if err != nil {
		return nil, fmt.Errorf("Failed to fill candidate versions. err: %s", err)
	}

	o.Packages.MergeNewVersion(upgradablePacks)

	// Setup changelog cache
	current := cache.Meta{
		Name:   o.getServerInfo().GetServerName(),
		Distro: o.getServerInfo().Distro,
		Packs:  upgradablePacks,
	}
	o.log.Debugf("Ensure changelog cache: %s", current.Name)
	if err := o.ensureChangelogCache(current); err != nil {
		return nil, err
	}

	// Collect CVE information of upgradable packages
	vulnInfos, err := o.scanVulnInfos(upgradablePacks)
	if err != nil {
		return nil, fmt.Errorf("Failed to scan unsecure packages. err: %s", err)
	}

	return vulnInfos, nil
}

func (o *debian) ensureChangelogCache(current cache.Meta) error {
	// Search from cache
	old, found, err := cache.DB.GetMeta(current.Name)
	if err != nil {
		return fmt.Errorf("Failed to get meta. err: %s", err)
	}
	if !found {
		o.log.Debugf("Not found in meta: %s", current.Name)
		err = cache.DB.EnsureBuckets(current)
		if err != nil {
			return fmt.Errorf("Failed to ensure buckets. err: %s", err)
		}
	} else {
		if current.Distro.Family != old.Distro.Family ||
			current.Distro.Release != old.Distro.Release {
			o.log.Debugf("Need to refesh meta: %s", current.Name)
			err = cache.DB.EnsureBuckets(current)
			if err != nil {
				return fmt.Errorf("Failed to ensure buckets. err: %s", err)
			}
		} else {
			o.log.Debugf("Reuse meta: %s", current.Name)
		}
	}

	if config.Conf.Debug {
		cache.DB.PrettyPrint(current)
	}
	return nil
}

func (o *debian) fillCandidateVersion(before models.PackageInfoList) (filled []models.PackageInfo, err error) {
	names := []string{}
	for _, p := range before {
		names = append(names, p.Name)
	}
	cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 apt-cache policy %s", strings.Join(names, " "))
	r := o.ssh(cmd, sudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	packChangelog := o.splitAptCachePolicy(r.Stdout)
	for k, v := range packChangelog {
		ver, err := o.parseAptCachePolicy(v, k)
		if err != nil {
			return nil, fmt.Errorf("Failed to parse %s", err)
		}
		p, found := before.FindByName(k)
		if !found {
			return nil, fmt.Errorf("Not found: %s", k)
		}
		p.NewVersion = ver.Candidate
		filled = append(filled, p)
	}
	return
}

func (o *debian) GetUpgradablePackNames() (packNames []string, err error) {
	cmd := util.PrependProxyEnv("LANGUAGE=en_US.UTF-8 apt-get upgrade --dry-run")
	r := o.ssh(cmd, sudo)
	if r.isSuccess(0, 1) {
		return o.parseAptGetUpgrade(r.Stdout)
	}
	return packNames, fmt.Errorf(
		"Failed to %s. status: %d, stdout: %s, stderr: %s",
		cmd, r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *debian) parseAptGetUpgrade(stdout string) (upgradableNames []string, err error) {
	startRe := regexp.MustCompile(`The following packages will be upgraded:`)
	stopRe := regexp.MustCompile(`^(\d+) upgraded.*`)
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

func (o *debian) scanVulnInfos(upgradablePacks []models.PackageInfo) (models.VulnInfos, error) {
	meta := cache.Meta{
		Name:   o.getServerInfo().GetServerName(),
		Distro: o.getServerInfo().Distro,
		Packs:  upgradablePacks,
	}

	type strarray []string
	resChan := make(chan struct {
		models.PackageInfo
		strarray
	}, len(upgradablePacks))
	errChan := make(chan error, len(upgradablePacks))
	reqChan := make(chan models.PackageInfo, len(upgradablePacks))
	defer close(resChan)
	defer close(errChan)
	defer close(reqChan)

	go func() {
		for _, pack := range upgradablePacks {
			reqChan <- pack
		}
	}()

	timeout := time.After(30 * 60 * time.Second)
	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range upgradablePacks {
		tasks <- func() {
			select {
			case pack := <-reqChan:
				func(p models.PackageInfo) {
					changelog := o.getChangelogCache(meta, p)
					if 0 < len(changelog) {
						cveIDs := o.getCveIDFromChangelog(changelog, p.Name, p.Version)
						resChan <- struct {
							models.PackageInfo
							strarray
						}{p, cveIDs}
						return
					}

					// if the changelog is not in cache or failed to get from local cache,
					// get the changelog of the package via internet.
					if cveIDs, err := o.scanPackageCveIDs(p); err != nil {
						errChan <- err
					} else {
						resChan <- struct {
							models.PackageInfo
							strarray
						}{p, cveIDs}
					}
				}(pack)
			}
		}
	}

	// { CVE ID: [packageInfo] }
	cvePackages := make(map[string][]models.PackageInfo)
	errs := []error{}
	for i := 0; i < len(upgradablePacks); i++ {
		select {
		case pair := <-resChan:
			pack := pair.PackageInfo
			cveIDs := pair.strarray
			for _, cveID := range cveIDs {
				cvePackages[cveID] = appendPackIfMissing(cvePackages[cveID], pack)
			}
			o.log.Infof("(%d/%d) Scanned %s-%s : %s",
				i+1, len(upgradablePacks), pair.Name, pair.PackageInfo.Version, cveIDs)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			errs = append(errs, fmt.Errorf("Timeout scanPackageCveIDs"))
		}
	}
	if 0 < len(errs) {
		return nil, fmt.Errorf("%v", errs)
	}

	var cveIDs []string
	for k := range cvePackages {
		cveIDs = append(cveIDs, k)
	}
	o.log.Debugf("%d Cves are found. cves: %v", len(cveIDs), cveIDs)
	var vinfos models.VulnInfos
	for k, v := range cvePackages {
		vinfos = append(vinfos, models.VulnInfo{
			CveID:    k,
			Packages: v,
		})
	}
	return vinfos, nil
}

func (o *debian) getChangelogCache(meta cache.Meta, pack models.PackageInfo) string {
	cachedPack, found := meta.FindPack(pack.Name)
	if !found {
		return ""
	}
	if cachedPack.NewVersion != pack.NewVersion {
		return ""
	}
	changelog, err := cache.DB.GetChangelog(meta.Name, pack.Name)
	if err != nil {
		o.log.Warnf("Failed to get changelog. bucket: %s, key:%s, err: %s",
			meta.Name, pack.Name, err)
		return ""
	}
	if len(changelog) == 0 {
		return ""
	}

	o.log.Debugf("Cache hit: %s, len: %d, %s...",
		meta.Name, len(changelog), util.Truncate(changelog, 30))
	return changelog
}

func (o *debian) scanPackageCveIDs(pack models.PackageInfo) ([]string, error) {
	cmd := ""
	switch o.Distro.Family {
	case "ubuntu":
		cmd = fmt.Sprintf(`apt-get changelog %s | grep '\(urgency\|CVE\)'`, pack.Name)
	case "debian":
		cmd = fmt.Sprintf(`aptitude changelog %s | grep '\(urgency\|CVE\)'`, pack.Name)
	}
	cmd = util.PrependProxyEnv(cmd)

	r := o.ssh(cmd, noSudo)
	if !r.isSuccess() {
		o.log.Warnf("Failed to SSH: %s", r)
		// Ignore this Error.
		return nil, nil
	}

	if 0 < len(strings.TrimSpace(r.Stdout)) {
		err := cache.DB.PutChangelog(o.getServerInfo().GetServerName(), pack.Name, r.Stdout)
		if err != nil {
			return nil, fmt.Errorf("Failed to put changelog into cache")
		}
	}
	// No error will be returned. Only logging.
	return o.getCveIDFromChangelog(r.Stdout, pack.Name, pack.Version), nil
}

func (o *debian) getCveIDFromChangelog(changelog string,
	packName string, versionOrLater string) []string {

	if cveIDs, err := o.parseChangelog(changelog, packName, versionOrLater); err == nil {
		return cveIDs
	}

	ver := strings.Split(versionOrLater, "ubuntu")[0]
	if cveIDs, err := o.parseChangelog(changelog, packName, ver); err == nil {
		return cveIDs
	}

	splittedByColon := strings.Split(versionOrLater, ":")
	if 1 < len(splittedByColon) {
		ver = splittedByColon[1]
	}
	cveIDs, err := o.parseChangelog(changelog, packName, ver)
	if err == nil {
		return cveIDs
	}

	// Only logging the error.
	o.log.Error(err)
	return []string{}
}

// Collect CVE-IDs included in the changelog.
// The version which specified in argument(versionOrLater) is excluded.
func (o *debian) parseChangelog(changelog string,
	packName string, versionOrLater string) (cveIDs []string, err error) {

	cveRe := regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)
	stopRe := regexp.MustCompile(fmt.Sprintf(`\(%s\)`, regexp.QuoteMeta(versionOrLater)))
	stopLineFound := false
	lines := strings.Split(changelog, "\n")
	for _, line := range lines {
		if matche := stopRe.MatchString(line); matche {
			o.log.Debugf("Found the stop line. line: %s", line)
			stopLineFound = true
			break
		} else if matches := cveRe.FindAllString(line, -1); 0 < len(matches) {
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

func (o *debian) splitAptCachePolicy(stdout string) map[string]string {
	//  re := regexp.MustCompile(`(?m:^[^ \t]+:$)`)
	re := regexp.MustCompile(`(?m:^[^ \t]+:\r\n)`)
	ii := re.FindAllStringIndex(stdout, -1)
	ri := []int{}
	for i := len(ii) - 1; 0 <= i; i-- {
		ri = append(ri, ii[i][0])
	}
	splitted := []string{}
	lasti := len(stdout)
	for _, i := range ri {
		splitted = append(splitted, stdout[i:lasti])
		lasti = i
	}

	packChangelog := map[string]string{}
	for _, r := range splitted {
		packName := r[:strings.Index(r, ":")]
		packChangelog[packName] = r
	}
	return packChangelog
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
