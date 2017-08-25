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
	"strconv"
	"strings"
	"time"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"

	"github.com/knqyf263/go-deb-version"
)

// inherit OsTypeInterface
type debian struct {
	base
}

// NewDebian is constructor
func newDebian(c config.ServerInfo) *debian {
	d := &debian{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = util.NewCustomLogger(c)
	d.setServerInfo(c)
	return d
}

// Ubuntu, Debian, Raspbian
// https://github.com/serverspec/specinfra/blob/master/lib/specinfra/helper/detect_os/debian.rb
func detectDebian(c config.ServerInfo) (itsMe bool, deb osTypeInterface, err error) {
	deb = newDebian(c)

	if r := exec(c, "ls /etc/debian_version", noSudo); !r.isSuccess() {
		if r.Error != nil {
			return false, deb, nil
		}
		if r.ExitStatus == 255 {
			return false, deb, fmt.Errorf("Unable to connect via SSH. Check SSH settings. If you have never SSH to the host to be scanned, SSH to the host before scanning in order to add the HostKey. %s@%s port: %s\n%s", c.User, c.Host, c.Port, r)
		}
		util.Log.Debugf("Not Debian like Linux. %s", r)
		return false, deb, nil
	}

	// Raspbian
	// lsb_release in Raspbian Jessie returns 'Distributor ID: Raspbian'.
	// However, lsb_release in Raspbian Wheezy returns 'Distributor ID: Debian'.
	if r := exec(c, "cat /etc/issue", noSudo); r.isSuccess() {
		//  e.g.
		//  Raspbian GNU/Linux 7 \n \l
		result := strings.Fields(r.Stdout)
		if len(result) > 2 && result[0] == config.Raspbian {
			distro := strings.ToLower(trim(result[0]))
			deb.setDistro(distro, trim(result[2]))
			return true, deb, nil
		}
	}

	if r := exec(c, "lsb_release -ir", noSudo); r.isSuccess() {
		//  e.g.
		//  root@fa3ec524be43:/# lsb_release -ir
		//  Distributor ID:	Ubuntu
		//  Release:	14.04
		re := regexp.MustCompile(`(?s)^Distributor ID:\s*(.+?)\n*Release:\s*(.+?)$`)
		result := re.FindStringSubmatch(trim(r.Stdout))

		if len(result) == 0 {
			deb.setDistro("debian/ubuntu", "unknown")
			util.Log.Warnf(
				"Unknown Debian/Ubuntu version. lsb_release -ir: %s", r)
		} else {
			distro := strings.ToLower(trim(result[1]))
			deb.setDistro(distro, trim(result[2]))
		}
		return true, deb, nil
	}

	if r := exec(c, "cat /etc/lsb-release", noSudo); r.isSuccess() {
		//  e.g.
		//  DISTRIB_ID=Ubuntu
		//  DISTRIB_RELEASE=14.04
		//  DISTRIB_CODENAME=trusty
		//  DISTRIB_DESCRIPTION="Ubuntu 14.04.2 LTS"
		re := regexp.MustCompile(`(?s)^DISTRIB_ID=(.+?)\n*DISTRIB_RELEASE=(.+?)\n.*$`)
		result := re.FindStringSubmatch(trim(r.Stdout))
		if len(result) == 0 {
			util.Log.Warnf(
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
	if r := exec(c, cmd, noSudo); r.isSuccess() {
		deb.setDistro(config.Debian, trim(r.Stdout))
		return true, deb, nil
	}

	util.Log.Debugf("Not Debian like Linux: %s", c.ServerName)
	return false, deb, nil
}

func trim(str string) string {
	return strings.TrimSpace(str)
}

func (o *debian) checkIfSudoNoPasswd() error {
	if config.Conf.Deep || o.Distro.Family == config.Raspbian {
		cmd := util.PrependProxyEnv("apt-get update")
		o.log.Infof("Checking... sudo %s", cmd)
		r := o.exec(cmd, sudo)
		if !r.isSuccess() {
			o.log.Errorf("sudo error on %s", r)
			return fmt.Errorf("Failed to sudo: %s", r)
		}
		o.log.Infof("Sudo... Pass")
		return nil
	}

	o.log.Infof("sudo ... No need")
	return nil
}

func (o *debian) checkDependencies() error {
	packNames := []string{}

	switch o.Distro.Family {
	case config.Ubuntu, config.Raspbian:
		o.log.Infof("Dependencies... No need")
		return nil

	case config.Debian:
		// https://askubuntu.com/a/742844
		packNames = append(packNames, "reboot-notifier")

		if !config.Conf.Deep {
			// Debian needs aptitude to get changelogs.
			// Because unable to get changelogs via apt-get changelog on Debian.
			packNames = append(packNames, "aptitude")
		}

	default:
		return fmt.Errorf("Not implemented yet: %s", o.Distro)
	}

	for _, name := range packNames {
		//TODO --show-format
		cmd := "dpkg-query -W " + name
		if r := o.exec(cmd, noSudo); !r.isSuccess() {
			msg := fmt.Sprintf("%s is not installed", name)
			o.log.Errorf(msg)
			return fmt.Errorf(msg)
		}
	}
	o.log.Infof("Dependencies... Pass")
	return nil
}

func (o *debian) scanPackages() error {
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	rebootRequired, err := o.rebootRequired()
	if err != nil {
		o.log.Errorf("Failed to detect the kernel reboot required: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Version:        version,
		Release:        release,
		RebootRequired: rebootRequired,
	}

	installed, updatable, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	o.Packages = installed

	if config.Conf.Deep || o.Distro.Family == config.Raspbian {
		unsecures, err := o.scanUnsecurePackages(updatable)
		if err != nil {
			o.log.Errorf("Failed to scan vulnerable packages: %s", err)
			return err
		}
		o.VulnInfos = unsecures
		return nil
	}
	return nil
}

// https://askubuntu.com/a/742844
func (o *debian) rebootRequired() (bool, error) {
	r := o.exec("test -f /var/run/reboot-required", noSudo)
	switch r.ExitStatus {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, fmt.Errorf("Failed to check reboot reauired: %s", r)
	}
}

func (o *debian) scanInstalledPackages() (models.Packages, models.Packages, error) {
	installed, updatable := models.Packages{}, models.Packages{}
	r := o.exec("dpkg-query -W", noSudo)
	if !r.isSuccess() {
		return nil, nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	//  e.g.
	//  curl	7.19.7-40.el6_6.4
	//  openldap	2.4.39-8.el6
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		if trimmed := strings.TrimSpace(line); len(trimmed) != 0 {
			name, version, err := o.parseScannedPackagesLine(trimmed)
			if err != nil {
				return nil, nil, fmt.Errorf(
					"Debian: Failed to parse package line: %s", line)
			}
			installed[name] = models.Package{
				Name:    name,
				Version: version,
			}
		}
	}

	updatableNames, err := o.getUpdatablePackNames()
	if err != nil {
		return nil, nil, err
	}
	for _, name := range updatableNames {
		for _, pack := range installed {
			if pack.Name == name {
				updatable[name] = pack
				break
			}
		}
	}

	// Fill the candidate versions of upgradable packages
	err = o.fillCandidateVersion(updatable)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to fill candidate versions. err: %s", err)
	}
	installed.MergeNewVersion(updatable)

	return installed, updatable, nil
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

func (o *debian) aptGetUpdate() error {
	o.log.Infof("apt-get update...")
	cmd := util.PrependProxyEnv("apt-get update")
	if r := o.exec(cmd, sudo); !r.isSuccess() {
		return fmt.Errorf("Failed to SSH: %s", r)
	}
	return nil
}

func (o *debian) scanUnsecurePackages(updatable models.Packages) (models.VulnInfos, error) {
	o.aptGetUpdate()

	// Setup changelog cache
	current := cache.Meta{
		Name:   o.getServerInfo().GetServerName(),
		Distro: o.getServerInfo().Distro,
		Packs:  updatable,
	}

	o.log.Debugf("Ensure changelog cache: %s", current.Name)
	meta, err := o.ensureChangelogCache(current)
	if err != nil {
		return nil, err
	}

	// Collect CVE information of upgradable packages
	vulnInfos, err := o.scanVulnInfos(updatable, meta)
	if err != nil {
		return nil, fmt.Errorf("Failed to scan unsecure packages. err: %s", err)
	}

	return vulnInfos, nil
}

func (o *debian) ensureChangelogCache(current cache.Meta) (*cache.Meta, error) {
	// Search from cache
	cached, found, err := cache.DB.GetMeta(current.Name)
	if err != nil {
		return nil, fmt.Errorf(
			"Failed to get meta. Please remove cache.db and then try again. err: %s", err)
	}

	if !found {
		o.log.Debugf("Not found in meta: %s", current.Name)
		err = cache.DB.EnsureBuckets(current)
		if err != nil {
			return nil, fmt.Errorf("Failed to ensure buckets. err: %s", err)
		}
		return &current, nil
	}

	if current.Distro.Family != cached.Distro.Family ||
		current.Distro.Release != cached.Distro.Release {
		o.log.Debugf("Need to refesh meta: %s", current.Name)
		err = cache.DB.EnsureBuckets(current)
		if err != nil {
			return nil, fmt.Errorf("Failed to ensure buckets. err: %s", err)
		}
		return &current, nil

	}

	o.log.Debugf("Reuse meta: %s", current.Name)
	if config.Conf.Debug {
		cache.DB.PrettyPrint(current)
	}
	return &cached, nil
}

func (o *debian) fillCandidateVersion(updatables models.Packages) (err error) {
	names := []string{}
	for name := range updatables {
		names = append(names, name)
	}
	cmd := fmt.Sprintf("LANGUAGE=en_US.UTF-8 apt-cache policy %s", strings.Join(names, " "))
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return fmt.Errorf("Failed to SSH: %s", r)
	}
	packChangelog := o.splitAptCachePolicy(r.Stdout)
	for k, v := range packChangelog {
		ver, err := o.parseAptCachePolicy(v, k)
		if err != nil {
			return fmt.Errorf("Failed to parse %s", err)
		}
		pack, ok := updatables[k]
		if !ok {
			return fmt.Errorf("Not found: %s", k)
		}
		pack.NewVersion = ver.Candidate
		updatables[k] = pack
	}
	return
}

func (o *debian) getUpdatablePackNames() (packNames []string, err error) {
	cmd := util.PrependProxyEnv("LANGUAGE=en_US.UTF-8 apt-get dist-upgrade --dry-run")
	r := o.exec(cmd, noSudo)
	if r.isSuccess(0, 1) {
		return o.parseAptGetUpgrade(r.Stdout)
	}
	return packNames, fmt.Errorf(
		"Failed to %s. status: %d, stdout: %s, stderr: %s",
		cmd, r.ExitStatus, r.Stdout, r.Stderr)
}

func (o *debian) parseAptGetUpgrade(stdout string) (updatableNames []string, err error) {
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
			nUpdatable, err := strconv.Atoi(result[1])
			if err != nil {
				return nil, fmt.Errorf(
					"Failed to scan upgradable packages number. line: %s", line)
			}
			if nUpdatable != len(updatableNames) {
				return nil, fmt.Errorf(
					"Failed to scan upgradable packages, expected: %s, detected: %d",
					result[1], len(updatableNames))
			}
			stopLineFound = true
			o.log.Debugf("Found the stop line. line: %s", line)
			break
		}
		updatableNames = append(updatableNames, strings.Fields(line)...)
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

// DetectedCveID has CveID, Confidence and DetectionMethod fields
// LenientMatching will be true if this vulnerability is not detected by accurate version matching.
// see https://github.com/future-architect/vuls/pull/328
type DetectedCveID struct {
	CveID      string
	Confidence models.Confidence
}

func (o *debian) scanVulnInfos(updatablePacks models.Packages, meta *cache.Meta) (models.VulnInfos, error) {
	type response struct {
		pack           *models.Package
		DetectedCveIDs []DetectedCveID
	}
	resChan := make(chan response, len(updatablePacks))
	errChan := make(chan error, len(updatablePacks))
	reqChan := make(chan models.Package, len(updatablePacks))
	defer close(resChan)
	defer close(errChan)
	defer close(reqChan)

	go func() {
		for _, pack := range updatablePacks {
			reqChan <- pack
		}
	}()

	timeout := time.After(30 * 60 * time.Second)
	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range updatablePacks {
		tasks <- func() {
			select {
			case pack := <-reqChan:
				func(p models.Package) {
					changelog := o.getChangelogCache(meta, p)
					if 0 < len(changelog) {
						cveIDs, pack := o.getCveIDsFromChangelog(changelog, p.Name, p.Version)
						resChan <- response{pack, cveIDs}
						return
					}

					// if the changelog is not in cache or failed to get from local cache,
					// get the changelog of the package via internet.
					// After that, store it in the cache.
					if cveIDs, pack, err := o.scanPackageCveIDs(p); err != nil {
						errChan <- err
					} else {
						resChan <- response{pack, cveIDs}
					}
				}(pack)
			}
		}
	}

	// { DetectedCveID{} : [package] }
	cvePackages := make(map[DetectedCveID][]string)
	errs := []error{}
	for i := 0; i < len(updatablePacks); i++ {
		select {
		case response := <-resChan:
			if response.pack == nil {
				continue
			}
			o.Packages[response.pack.Name] = *response.pack
			cves := response.DetectedCveIDs
			for _, cve := range cves {
				packNames, ok := cvePackages[cve]
				if ok {
					packNames = append(packNames, response.pack.Name)
				} else {
					packNames = []string{response.pack.Name}
				}
				cvePackages[cve] = packNames
			}
			o.log.Infof("(%d/%d) Scanned %s: %s",
				i+1, len(updatablePacks), response.pack.Name, cves)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			errs = append(errs, fmt.Errorf("Timeout scanPackageCveIDs"))
		}
	}
	if 0 < len(errs) {
		return nil, fmt.Errorf("%v", errs)
	}

	var cveIDs []DetectedCveID
	for k := range cvePackages {
		cveIDs = append(cveIDs, k)
	}
	o.log.Debugf("%d Cves are found. cves: %v", len(cveIDs), cveIDs)
	vinfos := models.VulnInfos{}
	for cveID, names := range cvePackages {
		affected := models.PackageStatuses{}
		for _, n := range names {
			affected = append(affected, models.PackageStatus{Name: n})
		}

		vinfos[cveID.CveID] = models.VulnInfo{
			CveID:            cveID.CveID,
			Confidence:       cveID.Confidence,
			AffectedPackages: affected,
		}
	}

	// Update meta package information of changelog cache to the latest one.
	meta.Packs = updatablePacks
	if err := cache.DB.RefreshMeta(*meta); err != nil {
		return nil, err
	}

	return vinfos, nil
}

func (o *debian) getChangelogCache(meta *cache.Meta, pack models.Package) string {
	cachedPack, found := meta.Packs[pack.Name]
	if !found {
		o.log.Debugf("Not found in cache: %s", pack.Name)
		return ""
	}

	if cachedPack.NewVersion != pack.NewVersion {
		o.log.Debugf("Expired: %s, cache: %s, new: %s",
			pack.Name, cachedPack.NewVersion, pack.NewVersion)
		return ""
	}
	changelog, err := cache.DB.GetChangelog(meta.Name, pack.Name)
	if err != nil {
		o.log.Warnf("Failed to get changelog. bucket: %s, key:%s, err: %s",
			meta.Name, pack.Name, err)
		return ""
	}
	if len(changelog) == 0 {
		o.log.Debugf("Empty string: %s", pack.Name)
		return ""
	}

	o.log.Debugf("Hit: %s, %s, cache: %s, new: %s len: %d, %s...",
		meta.Name, pack.Name, cachedPack.NewVersion, pack.NewVersion, len(changelog), util.Truncate(changelog, 30))
	return changelog
}

func (o *debian) scanPackageCveIDs(pack models.Package) ([]DetectedCveID, *models.Package, error) {
	cmd := ""
	switch o.Distro.Family {
	case config.Ubuntu, config.Raspbian:
		cmd = fmt.Sprintf(`PAGER=cat apt-get -q=2 changelog %s`, pack.Name)
	case config.Debian:
		cmd = fmt.Sprintf(`PAGER=cat aptitude -q=2 changelog %s`, pack.Name)
	}
	cmd = util.PrependProxyEnv(cmd)

	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		o.log.Warnf("Failed to SSH: %s", r)
		// Ignore this Error.
		return nil, nil, nil
	}

	stdout := strings.Replace(r.Stdout, "\r", "", -1)
	cveIDs, clogFilledPack := o.getCveIDsFromChangelog(stdout, pack.Name, pack.Version)

	if clogFilledPack.Changelog.Method != models.FailedToGetChangelog {
		err := cache.DB.PutChangelog(
			o.getServerInfo().GetServerName(), pack.Name, pack.Changelog.Contents)
		if err != nil {
			return nil, nil, fmt.Errorf("Failed to put changelog into cache")
		}
	}

	// No error will be returned. Only logging.
	return cveIDs, clogFilledPack, nil
}

func (o *debian) getCveIDsFromChangelog(
	changelog, name, ver string) ([]DetectedCveID, *models.Package) {

	if cveIDs, pack, err := o.parseChangelog(
		changelog, name, ver, models.ChangelogExactMatch); err == nil {
		return cveIDs, pack
	}

	var verAfterColon string

	splittedByColon := strings.Split(ver, ":")
	if 1 < len(splittedByColon) {
		verAfterColon = splittedByColon[1]
		if cveIDs, pack, err := o.parseChangelog(
			changelog, name, verAfterColon, models.ChangelogLenientMatch); err == nil {
			return cveIDs, pack
		}
	}

	delim := []string{"+", "~", "build"}
	switch o.Distro.Family {
	case config.Ubuntu:
		delim = append(delim, config.Ubuntu)
	case config.Debian:
	case config.Raspbian:
	}

	for _, d := range delim {
		ss := strings.Split(ver, d)
		if 1 < len(ss) {
			if cveIDs, pack, err := o.parseChangelog(
				changelog, name, ss[0], models.ChangelogLenientMatch); err == nil {
				return cveIDs, pack
			}
		}

		ss = strings.Split(verAfterColon, d)
		if 1 < len(ss) {
			if cveIDs, pack, err := o.parseChangelog(
				changelog, name, ss[0], models.ChangelogLenientMatch); err == nil {
				return cveIDs, pack
			}
		}
	}

	// Only logging the error.
	o.log.Warnf("Failed to find the version in changelog: %s-%s", name, ver)
	o.log.Debugf("Changelog of : %s-%s", name, ver, changelog)

	// If the version is not in changelog, return entire changelog to put into cache
	pack := o.Packages[name]
	pack.Changelog = models.Changelog{
		Contents: changelog,
		Method:   models.FailedToFindVersionInChangelog,
	}

	return []DetectedCveID{}, &pack
}

var cveRe = regexp.MustCompile(`(CVE-\d{4}-\d{4,})`)

// Collect CVE-IDs included in the changelog.
// The version specified in argument(versionOrLater) is used to compare.
func (o *debian) parseChangelog(changelog, name, ver string, confidence models.Confidence) ([]DetectedCveID, *models.Package, error) {
	installedVer, err := version.NewVersion(ver)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse installed version: %s, %s", ver, err)
	}
	buf, cveIDs := []string{}, []string{}
	scanner := bufio.NewScanner(strings.NewReader(changelog))
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		buf = append(buf, line)
		if matches := cveRe.FindAllString(line, -1); 0 < len(matches) {
			for _, m := range matches {
				cveIDs = util.AppendIfMissing(cveIDs, m)
			}
		}

		ss := strings.Fields(line)
		if len(ss) < 2 {
			continue
		}

		if !strings.HasPrefix(ss[1], "(") || !strings.HasSuffix(ss[1], ")") {
			continue
		}
		clogVer, err := version.NewVersion(ss[1][1 : len(ss[1])-1])
		if err != nil {
			continue
		}
		if installedVer.Equal(clogVer) || installedVer.GreaterThan(clogVer) {
			found = true
			break
		}
	}

	if !found {
		pack := o.Packages[name]
		pack.Changelog = models.Changelog{
			Contents: "",
			Method:   models.FailedToFindVersionInChangelog,
		}
		return nil, &pack, fmt.Errorf(
			"Failed to scan CVE IDs. The version is not in changelog. name: %s, version: %s",
			name, ver)
	}

	clog := models.Changelog{
		Contents: strings.Join(buf[0:len(buf)-1], "\n"),
		Method:   confidence.DetectionMethod,
	}
	pack := o.Packages[name]
	pack.Changelog = clog

	cves := []DetectedCveID{}
	for _, id := range cveIDs {
		cves = append(cves, DetectedCveID{id, confidence})
	}

	return cves, &pack, nil
}

func (o *debian) splitAptCachePolicy(stdout string) map[string]string {
	re := regexp.MustCompile(`(?m:^[^ \t]+:\r?\n)`)
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
