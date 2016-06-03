package scan

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type bsd struct {
	linux
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
	//set sudo option flag
	c.SudoOpt = config.SudoOption{ExecBySudo: true}
	bsd.setServerInfo(c)

	if r := sshExec(c, "uname", noSudo); r.isSuccess() {
		if strings.Contains(r.Stdout, "FreeBSD") == true {
			if b := sshExec(c, "uname -r", noSudo); b.isSuccess() {
				bsd.setDistributionInfo("FreeBSD", b.Stdout)
			} else {
				return false, bsd
			}
			return true, bsd
		} else {
			return false, bsd
		}
	}
	return
}
func (o *bsd) install() error {
	//pkg upgrade
	cmd := "pkg upgrade"
	if r := o.ssh(cmd, sudo); !r.isSuccess() {
		msg := fmt.Sprintf("Failed to %s. status: %d, stdout: %s, stderr: %s",
			cmd, r.ExitStatus, r.Stdout, r.Stderr)
		o.log.Errorf(msg)
		return fmt.Errorf(msg)
	}
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
	if unsecurePacks, err = o.scanUnsecurePackages(packs); err != nil {
		o.log.Errorf("Failed to scan vulnerable packages")
		return err
	}
	o.setUnsecurePackages(unsecurePacks)
	return nil
}

func (o *bsd) scanInstalledPackages() (packs []models.PackageInfo, err error) {
	//pkg query is a FreeBSD to provide info on a certain package : %n=name %v=version: formatting for string split later
	r := o.ssh("pkg query '%n*%v'", noSudo)
	if !r.isSuccess() {
		return packs, fmt.Errorf(
			"Failed to scan packages. status: %d, stdout:%s, Stderr: %s",
			r.ExitStatus, r.Stdout, r.Stderr)
	}
	//same format as debain.go
	lines := strings.Split(r.Stdout, "\n")
	for _, line := range lines {
		//for every \n
		if trimmed := strings.TrimSpace(line); len(trimmed) != 0 {
			name, version, err := o.parseScanedPackagesLine(trimmed)
			if err != nil {
				return nil, fmt.Errorf("FreeBSD: Failed to parse package")
			}
			packs = append(packs, models.PackageInfo{
				Name:    name,
				Version: version,
			})
		}
	}
	return
}

func (o *bsd) parseScanedPackagesLine(line string) (name, version string, err error) {
	name = strings.Split(line, "*")[0]
	if len(strings.Split(line, "*")) == 2 {

		version = strings.Split(line, "*")[1]
	}
	return name, version, nil
}

func (o *bsd) checkRequiredPackagesInstalled() error {
	return nil
}

func (o *bsd) scanUnsecurePackages(packs []models.PackageInfo) ([]CvePacksInfo, error) {
	cmd := util.PrependProxyEnv("pkg version -l '>'")
	r := o.ssh(cmd, noSudo)
	if !r.isSuccess() {
		return nil, nil
	}
	match := regexp.MustCompile("(.)+[^[-](\\d)]")
	upgradablePackNames := match.FindAllString(r.Stdout, -1)

	// Convert package name to PackageInfo struct
	var unsecurePacks []models.PackageInfo
	var err error
	for _, name := range upgradablePackNames {
		for _, pack := range packs {
			if pack.Name == name {
				unsecurePacks = append(unsecurePacks, pack)
				break
			}
		}
	}
	/* unsecurePacks, err = o.fillCanidateVersion(unsecurePacks)
	if err != nil {
		return nil, fmt.Errorf("Failed to fill canidate versions. err: %s", err)
	}
	*/

	// Collect CVE information of upgradable packages
	cvePacksInfos, err := o.scanPackageCveInfos(unsecurePacks)
	if err != nil {
		return nil, fmt.Errorf("Failed to scan unsecure packages. err: %s", err)
	}

	return cvePacksInfos, nil
}

func (o *bsd) scanPackageCveInfos(unsecurePacks []models.PackageInfo) (cvePacksList CvePacksList, err error) {

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

	errs := []error{}
	for i := 0; i < len(unsecurePacks); i++ {
		o.log.Info(unsecurePacks[i])
		select {
		case pair := <-resChan:
			pack := pair.PackageInfo
			cveIDs := pair.strarray
			for _, cveID := range cveIDs {
				cvePackages[cveID] = appendPackIfMissing(cvePackages[cveID], pack)
			}
			o.log.Infof("(%d/%d) Scanned %s-%s : %s",
				i+1, len(unsecurePacks), pair.Name, pair.PackageInfo.Version, cveIDs)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, fmt.Errorf("Timeout scanPackageCveIDs")
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

	o.log.Info("Fetching CVE details...")
	cveDetails, err := cveapi.CveClient.FetchCveDetails(cveIDs)
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
	return
}

func (o *bsd) scanPackageCveIDs(pack models.PackageInfo) ([]string, error) {
	cmd := fmt.Sprintf("pkg audit -F %s | grep CVE-\\w", pack.Name)
	cmd = util.PrependProxyEnv(cmd)

	r := o.ssh(cmd, noSudo)
	if !r.isSuccess() {
		o.log.Warnf("Failed to %s, status: %d, stdout: %s, stderr: %s", cmd, r.ExitStatus, r.Stdout, r.Stderr)
		return nil, nil
	}
	match := regexp.MustCompile("(CVE-\\d{4}-\\d{4})")
	return match.FindAllString(r.Stdout, -1), nil
}
