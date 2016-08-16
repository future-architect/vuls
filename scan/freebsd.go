package scan

import (
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type bsd struct {
	base
}

// NewBSD constructor
func newBsd(c config.ServerInfo) *bsd {
	d := &bsd{}
	d.log = util.NewCustomLogger(c)
	return d
}

//https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/freebsd.rb
func detectFreebsd(c config.ServerInfo) (itsMe bool, bsd osTypeInterface) {
	bsd = newBsd(c)
	c.Family = "FreeBSD"
	if r := sshExec(c, "uname", noSudo); r.isSuccess() {
		if strings.Contains(r.Stdout, "FreeBSD") == true {
			if b := sshExec(c, "uname -r", noSudo); b.isSuccess() {
				bsd.setDistributionInfo("FreeBSD", strings.TrimSpace(b.Stdout))
				bsd.setServerInfo(c)
				return true, bsd
			}
		}
	}
	Log.Debugf("Not FreeBSD. servernam: %s", c.ServerName)
	return false, bsd
}

func (o *bsd) checkIfSudoNoPasswd() error {
	// FreeBSD doesn't need root privilege
	o.log.Infof("sudo ... OK")
	return nil
}

func (o *bsd) install() error {
	return nil
}

func (o *bsd) checkRequiredPackagesInstalled() error {
	return nil
}

func (o *bsd) scanPackages() error {
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

func (o *bsd) scanInstalledPackages() ([]models.PackageInfo, error) {
	cmd := util.PrependProxyEnv("pkg version -v")
	r := o.ssh(cmd, noSudo)
	if !r.isSuccess() {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	return o.parsePkgVersion(r.Stdout), nil
}

func (o *bsd) scanUnsecurePackages() (cvePacksList []CvePacksInfo, err error) {
	const vulndbPath = "/tmp/vuln.db"
	cmd := "rm -f " + vulndbPath
	r := o.ssh(cmd, noSudo)
	if !r.isSuccess(0) {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}

	cmd = util.PrependProxyEnv("pkg audit -F -r -f " + vulndbPath)
	r = o.ssh(cmd, noSudo)
	if !r.isSuccess(0, 1) {
		return nil, fmt.Errorf("Failed to SSH: %s", r)
	}
	if r.ExitStatus == 0 {
		// no vulnerabilities
		return []CvePacksInfo{}, nil
	}

	var packAdtRslt []pkgAuditResult
	blocks := o.splitIntoBlocks(r.Stdout)
	for _, b := range blocks {
		name, cveIDs, vulnID := o.parseBlock(b)
		if len(cveIDs) == 0 {
			continue
		}
		pack, found := o.Packages.FindByName(name)
		if !found {
			return nil, fmt.Errorf("Vulnerable package: %s is not found", name)
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

	cveIDs := []string{}
	for k := range cveIDAdtMap {
		cveIDs = append(cveIDs, k)
	}

	cveDetails, err := cveapi.CveClient.FetchCveDetails(cveIDs)
	if err != nil {
		return nil, err
	}
	o.log.Info("Done")

	for _, d := range cveDetails {
		packs := []models.PackageInfo{}
		for _, r := range cveIDAdtMap[d.CveID] {
			packs = append(packs, r.pack)
		}

		disAdvs := []models.DistroAdvisory{}
		for _, r := range cveIDAdtMap[d.CveID] {
			disAdvs = append(disAdvs, models.DistroAdvisory{
				AdvisoryID: r.vulnIDCveIDs.vulnID,
			})
		}

		cvePacksList = append(cvePacksList, CvePacksInfo{
			CveID:            d.CveID,
			CveDetail:        d,
			Packs:            packs,
			DistroAdvisories: disAdvs,
		})
	}
	return
}

func (o *bsd) parsePkgVersion(stdout string) (packs []models.PackageInfo) {
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
			packs = append(packs, models.PackageInfo{
				Name:    name,
				Version: ver,
			})
		case "<":
			candidate := strings.TrimSuffix(fields[6], ")")
			packs = append(packs, models.PackageInfo{
				Name:       name,
				Version:    ver,
				NewVersion: candidate,
			})
		}
	}
	return
}

type vulnIDCveIDs struct {
	vulnID string
	cveIDs []string
}

type pkgAuditResult struct {
	pack         models.PackageInfo
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
