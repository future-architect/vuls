package scan

import (
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
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
	getDistributionInfo() string
	checkRequiredPackagesInstalled() error
	scanPackages() error
	scanVulnByCpeName() error
	install() error
	convertToModel() (models.ScanResult, error)

	runningContainers() ([]config.Container, error)
	exitedContainers() ([]config.Container, error)
	allContainers() ([]config.Container, error)

	getErrs() []error
	setErrs([]error)
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
	return s[i].CveDetail.CvssScore(config.Conf.Lang) >
		s[j].CveDetail.CvssScore(config.Conf.Lang)
}

func detectOS(c config.ServerInfo) (osType osTypeInterface) {
	var itsMe bool
	itsMe, osType = detectDebian(c)
	if itsMe {
		return
	}
	itsMe, osType = detectRedhat(c)
	if itsMe {
		return
	}

	osType.setErrs([]error{fmt.Errorf("Unknown OS Type")})
	return
}

// InitServers detect the kind of OS distribution of target servers
func InitServers(localLogger *logrus.Entry) error {
	Log = localLogger

	hosts, err := detectServerOSes()
	if err != nil {
		return fmt.Errorf("Failed to detect server OSes. err: %s", err)
	}
	servers = hosts

	Log.Info("Detecting Container OS...")
	containers, err := detectContainerOSes()
	if err != nil {
		return fmt.Errorf("Failed to detect Container OSes. err: %s", err)
	}
	servers = append(servers, containers...)
	return nil
}

func detectServerOSes() (oses []osTypeInterface, err error) {
	osTypeChan := make(chan osTypeInterface, len(config.Conf.Servers))
	defer close(osTypeChan)
	for _, s := range config.Conf.Servers {
		go func(s config.ServerInfo) {
			//TODO handling Unknown OS
			osTypeChan <- detectOS(s)
		}(s)
	}

	timeout := time.After(300 * time.Second)
	for i := 0; i < len(config.Conf.Servers); i++ {
		select {
		case res := <-osTypeChan:
			if 0 < len(res.getErrs()) {
				continue
			}
			Log.Infof("(%d/%d) Detected %s: %s",
				i+1, len(config.Conf.Servers),
				res.getServerInfo().ServerName,
				res.getDistributionInfo())
			oses = append(oses, res)
		case <-timeout:
			msg := "Timeout occurred while detecting"
			Log.Error(msg)
			for servername := range config.Conf.Servers {
				found := false
				for _, o := range oses {
					if servername == o.getServerInfo().ServerName {
						found = true
						break
					}
				}
				if !found {
					Log.Errorf("Failed to detect. servername: %s", servername)
				}
			}
			return oses, fmt.Errorf(msg)
		}
	}

	errorOccurred := false
	for _, osi := range oses {
		if errs := osi.getErrs(); 0 < len(errs) {
			errorOccurred = true
			Log.Errorf("Some errors occurred on %s",
				osi.getServerInfo().ServerName)
			for _, err := range errs {
				Log.Error(err)
			}
		}
	}
	if errorOccurred {
		return oses, fmt.Errorf("Some errors occurred")
	}
	return
}

func detectContainerOSes() (oses []osTypeInterface, err error) {
	osTypesChan := make(chan []osTypeInterface, len(servers))
	defer close(osTypesChan)
	for _, s := range servers {
		go func(s osTypeInterface) {
			osTypesChan <- detectContainerOSesOnServer(s)
		}(s)
	}

	timeout := time.After(300 * time.Second)
	for i := 0; i < len(config.Conf.Servers); i++ {
		select {
		case res := <-osTypesChan:
			for _, osi := range res {
				if 0 < len(osi.getErrs()) {
					continue
				}
				sinfo := osi.getServerInfo()
				Log.Infof("Detected %s/%s on %s: %s",
					sinfo.Container.ContainerID, sinfo.Container.Name,
					sinfo.ServerName, osi.getDistributionInfo())
			}
			oses = append(oses, res...)
		case <-timeout:
			msg := "Timeout occurred while detecting"
			Log.Error(msg)
			for servername := range config.Conf.Servers {
				found := false
				for _, o := range oses {
					if servername == o.getServerInfo().ServerName {
						found = true
						break
					}
				}
				if !found {
					Log.Errorf("Failed to detect. servername: %s", servername)
				}
			}
			return oses, fmt.Errorf(msg)
		}
	}

	errorOccurred := false
	for _, osi := range oses {
		if errs := osi.getErrs(); 0 < len(errs) {
			errorOccurred = true
			Log.Errorf("Some errors occurred on %s",
				osi.getServerInfo().ServerName)
			for _, err := range errs {
				Log.Error(err)
			}
		}
	}
	if errorOccurred {
		return oses, fmt.Errorf("Some errors occurred")
	}
	return
}

func detectContainerOSesOnServer(containerHost osTypeInterface) (oses []osTypeInterface) {
	containerHostInfo := containerHost.getServerInfo()
	if len(containerHostInfo.Containers) == 0 {
		return
	}

	running, err := containerHost.runningContainers()
	if err != nil {
		containerHost.setErrs([]error{fmt.Errorf(
			"Failed to get running containers on %s. err: %s",
			containerHost.getServerInfo().ServerName, err)})
		return append(oses, containerHost)
	}

	if containerHostInfo.Containers[0] == "${running}" {
		for _, containerInfo := range running {
			copied := containerHostInfo
			copied.SetContainer(config.Container{
				ContainerID: containerInfo.ContainerID,
				Name:        containerInfo.Name,
			})
			os := detectOS(copied)
			oses = append(oses, os)
		}
		return oses
	}

	exitedContainers, err := containerHost.exitedContainers()
	if err != nil {
		containerHost.setErrs([]error{fmt.Errorf(
			"Failed to get exited containers on %s. err: %s",
			containerHost.getServerInfo().ServerName, err)})
		return append(oses, containerHost)
	}

	var exited, unknown []string
	for _, container := range containerHostInfo.Containers {
		found := false
		for _, c := range running {
			if c.ContainerID == container || c.Name == container {
				copied := containerHostInfo
				copied.SetContainer(c)
				os := detectOS(copied)
				oses = append(oses, os)
				found = true
				break
			}
		}

		if !found {
			foundInExitedContainers := false
			for _, c := range exitedContainers {
				if c.ContainerID == container || c.Name == container {
					exited = append(exited, container)
					foundInExitedContainers = true
					break
				}
			}
			if !foundInExitedContainers {
				unknown = append(unknown, container)
			}
		}
	}
	if 0 < len(exited) || 0 < len(unknown) {
		containerHost.setErrs([]error{fmt.Errorf(
			"Some containers on %s are exited or unknown. exited: %s, unknown: %s",
			containerHost.getServerInfo().ServerName, exited, unknown)})
		return append(oses, containerHost)
	}
	return oses
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
		return []error{fmt.Errorf("No server defined. Check the configuration")}
	}

	Log.Info("Check required packages for scanning...")
	if errs := checkRequiredPackagesInstalled(); errs != nil {
		Log.Error("Please execute with [prepare] subcommand to install required packages before scanning")
		return errs
	}

	Log.Info("Scanning vulnerable OS packages...")
	if errs := scanPackages(); errs != nil {
		return errs
	}

	Log.Info("Scanning vulnerable software specified in the CPE...")
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
			return results, fmt.Errorf("Failed converting to model: %s", err)
		}
		results = append(results, r)
	}
	return
}
