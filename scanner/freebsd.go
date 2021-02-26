package scanner

import (
	"net"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// inherit OsTypeInterface
type bsd struct {
	base
}

// NewBSD constructor
func newBsd(c config.ServerInfo) *bsd {
	d := &bsd{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

//https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/freebsd.rb
func detectFreebsd(c config.ServerInfo) (bool, osTypeInterface) {
	// Prevent from adding `set -o pipefail` option
	c.Distro = config.Distro{Family: constant.FreeBSD}

	if r := exec(c, "uname", noSudo); r.isSuccess() {
		if strings.Contains(strings.ToLower(r.Stdout), constant.FreeBSD) == true {
			if b := exec(c, "freebsd-version", noSudo); b.isSuccess() {
				bsd := newBsd(c)
				rel := strings.TrimSpace(b.Stdout)
				bsd.setDistro(constant.FreeBSD, rel)
				return true, bsd
			}
		}
	}
	logging.Log.Debugf("Not FreeBSD. servernam: %s", c.ServerName)
	return false, nil
}

func (o *bsd) checkScanMode() error {
	if o.getServerInfo().Mode.IsOffline() {
		return xerrors.New("Remove offline scan mode, FreeBSD needs internet connection")
	}
	return nil
}

func (o *bsd) checkIfSudoNoPasswd() error {
	// FreeBSD doesn't need root privilege
	o.log.Infof("sudo ... No need")
	return nil
}

func (o *bsd) checkDeps() error {
	o.log.Infof("Dependencies... No need")
	return nil
}

func (o *bsd) preCure() error {
	if err := o.detectIPAddr(); err != nil {
		o.log.Warnf("Failed to detect IP addresses: %s", err)
		o.warns = append(o.warns, err)
	}
	// Ignore this error as it just failed to detect the IP addresses
	return nil
}

func (o *bsd) postScan() error {
	return nil
}

func (o *bsd) detectIPAddr() (err error) {
	r := o.exec("/sbin/ifconfig", noSudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to detect IP address: %v", r)
	}
	o.ServerInfo.IPv4Addrs, o.ServerInfo.IPv6Addrs = o.parseIfconfig(r.Stdout)
	return nil
}

func (l *base) parseIfconfig(stdout string) (ipv4Addrs []string, ipv6Addrs []string) {
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "inet") {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
			continue
		}
		if !ip.IsGlobalUnicast() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4Addrs = append(ipv4Addrs, ipv4.String())
		} else {
			ipv6Addrs = append(ipv6Addrs, ip.String())
		}
	}
	return
}

func (o *bsd) scanPackages() error {
	o.log.Infof("Scanning OS pkg in %s", o.getServerInfo().Mode)
	// collect the running kernel information
	release, version, err := o.runningKernel()
	if err != nil {
		o.log.Errorf("Failed to scan the running kernel version: %s", err)
		return err
	}
	o.Kernel = models.Kernel{
		Release: release,
		Version: version,
	}

	o.Kernel.RebootRequired, err = o.rebootRequired()
	if err != nil {
		err = xerrors.Errorf("Failed to detect the kernel reboot required: %w", err)
		o.log.Warnf("err: %+v", err)
		o.warns = append(o.warns, err)
		// Only warning this error
	}

	packs, err := o.scanInstalledPackages()
	if err != nil {
		o.log.Errorf("Failed to scan installed packages: %s", err)
		return err
	}
	o.Packages = packs

	unsecures, err := o.scanUnsecurePackages()
	if err != nil {
		o.log.Errorf("Failed to scan vulnerable packages: %s", err)
		return err
	}
	o.VulnInfos = unsecures
	return nil
}

func (o *bsd) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}

func (o *bsd) rebootRequired() (bool, error) {
	r := o.exec("freebsd-version -k", noSudo)
	if !r.isSuccess() {
		return false, xerrors.Errorf("Failed to SSH: %s", r)
	}
	return o.Kernel.Release != strings.TrimSpace(r.Stdout), nil
}

func (o *bsd) scanInstalledPackages() (models.Packages, error) {
	// https://github.com/future-architect/vuls/issues/1042
	cmd := util.PrependProxyEnv("pkg info")
	r := o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	pkgs := o.parsePkgInfo(r.Stdout)

	cmd = util.PrependProxyEnv("pkg version -v")
	r = o.exec(cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	// `pkg-audit` has a new version, overwrite it.
	for name, p := range o.parsePkgVersion(r.Stdout) {
		pkgs[name] = p
	}
	return pkgs, nil
}

func (o *bsd) scanUnsecurePackages() (models.VulnInfos, error) {
	const vulndbPath = "/tmp/vuln.db"
	cmd := "rm -f " + vulndbPath
	r := o.exec(cmd, noSudo)
	if !r.isSuccess(0) {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}

	cmd = util.PrependProxyEnv("pkg audit -F -r -f " + vulndbPath)
	r = o.exec(cmd, noSudo)
	if !r.isSuccess(0, 1) {
		return nil, xerrors.Errorf("Failed to SSH: %s", r)
	}
	if r.ExitStatus == 0 {
		// no vulnerabilities
		return nil, nil
	}

	packAdtRslt := []pkgAuditResult{}
	blocks := o.splitIntoBlocks(r.Stdout)
	for _, b := range blocks {
		name, cveIDs, vulnID := o.parseBlock(b)
		if len(cveIDs) == 0 {
			continue
		}
		pack, found := o.Packages[name]
		if !found {
			return nil, xerrors.Errorf("Vulnerable package: %s is not found", name)
		}
		packAdtRslt = append(packAdtRslt, pkgAuditResult{
			pack: pack,
			vulnIDCveIDs: vulnIDCveIDs{
				vulnID: vulnID,
				cveIDs: cveIDs,
			},
		})
	}

	// { CVE ID: []pkgAuditResult }
	cveIDAdtMap := make(map[string][]pkgAuditResult)
	for _, p := range packAdtRslt {
		for _, cid := range p.vulnIDCveIDs.cveIDs {
			cveIDAdtMap[cid] = append(cveIDAdtMap[cid], p)
		}
	}

	vinfos := models.VulnInfos{}
	for cveID := range cveIDAdtMap {
		packs := models.Packages{}
		for _, r := range cveIDAdtMap[cveID] {
			packs[r.pack.Name] = r.pack
		}

		disAdvs := []models.DistroAdvisory{}
		for _, r := range cveIDAdtMap[cveID] {
			disAdvs = append(disAdvs, models.DistroAdvisory{
				AdvisoryID: r.vulnIDCveIDs.vulnID,
			})
		}

		affected := models.PackageFixStatuses{}
		for name := range packs {
			affected = append(affected, models.PackageFixStatus{
				Name: name,
			})
		}
		vinfos[cveID] = models.VulnInfo{
			CveID:            cveID,
			AffectedPackages: affected,
			DistroAdvisories: disAdvs,
			Confidences:      models.Confidences{models.PkgAuditMatch},
		}
	}
	return vinfos, nil
}

func (o *bsd) parsePkgInfo(stdout string) models.Packages {
	packs := models.Packages{}
	lines := strings.Split(stdout, "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}

		packVer := fields[0]
		splitted := strings.Split(packVer, "-")
		ver := splitted[len(splitted)-1]
		name := strings.Join(splitted[:len(splitted)-1], "-")
		packs[name] = models.Package{
			Name:    name,
			Version: ver,
		}
	}
	return packs
}

func (o *bsd) parsePkgVersion(stdout string) models.Packages {
	packs := models.Packages{}
	lines := strings.Split(stdout, "\n")
	for _, l := range lines {
		fields := strings.Fields(l)
		if len(fields) < 2 {
			continue
		}

		packVer := fields[0]
		splitted := strings.Split(packVer, "-")
		ver := splitted[len(splitted)-1]
		name := strings.Join(splitted[:len(splitted)-1], "-")

		switch fields[1] {
		case "?", "=":
			packs[name] = models.Package{
				Name:    name,
				Version: ver,
			}
		case "<":
			candidate := strings.TrimSuffix(fields[6], ")")
			packs[name] = models.Package{
				Name:       name,
				Version:    ver,
				NewVersion: candidate,
			}
		case ">":
			o.log.Warnf("The installed version of the %s is newer than the current version. *This situation can arise with an out of date index file, or when testing new ports.*", name)
			packs[name] = models.Package{
				Name:    name,
				Version: ver,
			}
		}
	}
	return packs
}

type vulnIDCveIDs struct {
	vulnID string
	cveIDs []string
}

type pkgAuditResult struct {
	pack         models.Package
	vulnIDCveIDs vulnIDCveIDs
}

func (o *bsd) splitIntoBlocks(stdout string) (blocks []string) {
	lines := strings.Split(stdout, "\n")
	block := []string{}
	for _, l := range lines {
		if len(strings.TrimSpace(l)) == 0 {
			if 0 < len(block) {
				blocks = append(blocks, strings.Join(block, "\n"))
				block = []string{}
			}
			continue
		}
		block = append(block, strings.TrimSpace(l))
	}
	if 0 < len(block) {
		blocks = append(blocks, strings.Join(block, "\n"))
	}
	return
}

func (o *bsd) parseBlock(block string) (packName string, cveIDs []string, vulnID string) {
	lines := strings.Split(block, "\n")
	for _, l := range lines {
		if strings.HasSuffix(l, " is vulnerable:") {
			packVer := strings.Fields(l)[0]
			splitted := strings.Split(packVer, "-")
			packName = strings.Join(splitted[:len(splitted)-1], "-")
		} else if strings.HasPrefix(l, "CVE:") {
			cveIDs = append(cveIDs, strings.Fields(l)[1])
		} else if strings.HasPrefix(l, "WWW:") {
			splitted := strings.Split(l, "/")
			vulnID = strings.TrimSuffix(splitted[len(splitted)-1], ".html")
		}
	}
	return
}
