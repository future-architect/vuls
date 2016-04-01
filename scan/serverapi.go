package scan

import (
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
)

// Log for localhsot
var Log *logrus.Entry

var servers []osTypeInterface

// Base Interface of redhat, debian
type osTypeInterface interface {
	setServerInfo(config.ServerInfo)
	getServerInfo() config.ServerInfo
	setDistributionInfo(string, string)
	checkRequiredPackagesInstalled() error
	scanPackages() error
	scanVulnByCpeName() error
	install() error
	convertToModel() (models.ScanResult, error)
}

// osPackages included by linux struct
type osPackages struct {
	// installed packages
	Packages models.PackageInfoList

	// unsecure packages
	UnsecurePackages CvePacksList
}

func (p *osPackages) setPackages(pi models.PackageInfoList) {
	p.Packages = pi
}

func (p *osPackages) setUnsecurePackages(pi []CvePacksInfo) {
	p.UnsecurePackages = pi
}

// CvePacksList have CvePacksInfo list, getter/setter, sortable methods.
type CvePacksList []CvePacksInfo

// CvePacksInfo hold the CVE information.
type CvePacksInfo struct {
	CveID            string
	CveDetail        cve.CveDetail
	Packs            []models.PackageInfo
	DistroAdvisories []models.DistroAdvisory // for Aamazon, RHEL
	CpeNames         []string
	//  CvssScore float64
}

// FindByCveID find by CVEID
func (s CvePacksList) FindByCveID(cveID string) (pi CvePacksInfo, found bool) {
	for _, p := range s {
		if cveID == p.CveID {
			return p, true
		}
	}
	return CvePacksInfo{CveID: cveID}, false
}

// immutable
func (s CvePacksList) set(cveID string, cvePacksInfo CvePacksInfo) CvePacksList {
	for i, p := range s {
		if cveID == p.CveID {
			s[i] = cvePacksInfo
			return s
		}
	}
	return append(s, cvePacksInfo)
}

// Len implement Sort Interface
func (s CvePacksList) Len() int {
	return len(s)
}

// Swap implement Sort Interface
func (s CvePacksList) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less implement Sort Interface
func (s CvePacksList) Less(i, j int) bool {
	return s[i].CveDetail.CvssScore("en") > s[j].CveDetail.CvssScore("en")
}

func detectOs(c config.ServerInfo) (osType osTypeInterface) {
	var itsMe bool
	itsMe, osType = detectDebian(c)
	if itsMe {
		return
	}
	itsMe, osType = detectRedhat(c)
	return
}

// InitServers detect the kind of OS distribution of target servers
func InitServers(localLogger *logrus.Entry) (err error) {
	Log = localLogger
	if servers, err = detectServersOS(); err != nil {
		err = fmt.Errorf("Failed to detect OS")
	} else {
		Log.Debugf("%s", pp.Sprintf("%s", servers))
	}
	return
}

func detectServersOS() (osi []osTypeInterface, err error) {
	osTypeChan := make(chan osTypeInterface, len(config.Conf.Servers))
	defer close(osTypeChan)
	for _, s := range config.Conf.Servers {
		go func(s config.ServerInfo) {
			osTypeChan <- detectOs(s)
		}(s)
	}

	timeout := time.After(60 * time.Second)
	for i := 0; i < len(config.Conf.Servers); i++ {
		select {
		case res := <-osTypeChan:
			osi = append(osi, res)
		case <-timeout:
			Log.Error("Timeout Occured while detecting OS.")
			err = fmt.Errorf("Timeout!")
			return
		}
	}
	return
}

// Prepare installs requred packages to scan vulnerabilities.
func Prepare() []error {
	return parallelSSHExec(func(o osTypeInterface) error {
		if err := o.install(); err != nil {
			return err
		}
		return nil
	})
}

// Scan scan
func Scan() []error {
	if len(servers) == 0 {
		return []error{fmt.Errorf("Not initialize yet.")}
	}

	Log.Info("Check required packages for scanning...")
	if errs := checkRequiredPackagesInstalled(); errs != nil {
		Log.Error("Please execute with [prepare] subcommand to install required packages before scanning")
		return errs
	}

	Log.Info("Scanning vuluneable OS packages...")
	if errs := scanPackages(); errs != nil {
		return errs
	}

	Log.Info("Scanning vulnerable software specified in CPE...")
	if errs := scanVulnByCpeName(); errs != nil {
		return errs
	}
	return nil
}

func checkRequiredPackagesInstalled() []error {
	timeoutSec := 30 * 60
	return parallelSSHExec(func(o osTypeInterface) error {
		return o.checkRequiredPackagesInstalled()
	}, timeoutSec)
}

func scanPackages() []error {
	timeoutSec := 30 * 60
	return parallelSSHExec(func(o osTypeInterface) error {
		return o.scanPackages()
	}, timeoutSec)

}

// scanVulnByCpeName search vulnerabilities that specified in config file.
func scanVulnByCpeName() []error {
	timeoutSec := 30 * 60
	return parallelSSHExec(func(o osTypeInterface) error {
		return o.scanVulnByCpeName()
	}, timeoutSec)

}

// GetScanResults returns Scan Resutls
func GetScanResults() (results models.ScanResults, err error) {
	for _, s := range servers {
		r, err := s.convertToModel()
		if err != nil {
			return results, fmt.Errorf("Failed converting to model: %s.", err)
		}
		results = append(results, r)
	}
	return
}
