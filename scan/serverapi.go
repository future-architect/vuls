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

// Base Interface of redhat, debian, freebsd
type osTypeInterface interface {
	setServerInfo(config.ServerInfo)
	getServerInfo() config.ServerInfo

	setDistributionInfo(string, string)
	getDistributionInfo() string

	checkIfSudoNoPasswd() error
	detectPlatform() error
	getPlatform() models.Platform

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
	Packs            models.PackageInfoList
	DistroAdvisories []models.DistroAdvisory // for Aamazon, RHEL, FreeBSD
	CpeNames         []string
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
	var fatalErr error

	itsMe, osType, fatalErr = detectDebian(c)
	if fatalErr != nil {
		osType.setServerInfo(c)
		osType.setErrs([]error{fatalErr})
		return
	} else if itsMe {
		Log.Debugf("Debian like Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectRedhat(c); itsMe {
		Log.Debugf("Redhat like Linux. Host: %s:%s", c.Host, c.Port)
		return
	}
	if itsMe, osType = detectFreebsd(c); itsMe {
		Log.Debugf("FreeBSD. Host: %s:%s", c.Host, c.Port)
		return
	}
	osType.setServerInfo(c)
	osType.setErrs([]error{fmt.Errorf("Unknown OS Type")})
	return
}

// PrintSSHableServerNames print SSH-able servernames
func PrintSSHableServerNames() {
	Log.Info("SSH-able servers are below...")
	for _, s := range servers {
		if s.getServerInfo().IsContainer() {
			fmt.Printf("%s@%s ",
				s.getServerInfo().Container.Name,
				s.getServerInfo().ServerName,
			)
		} else {
			fmt.Printf("%s ", s.getServerInfo().ServerName)
		}
	}
	fmt.Printf("\n")
}

// InitServers detect the kind of OS distribution of target servers
func InitServers(localLogger *logrus.Entry) {
	Log = localLogger
	servers = detectServerOSes()
	containers := detectContainerOSes()
	servers = append(servers, containers...)
}

func detectServerOSes() (sshAbleOses []osTypeInterface) {
	Log.Info("Detecting OS of servers... ")
	osTypeChan := make(chan osTypeInterface, len(config.Conf.Servers))
	defer close(osTypeChan)
	for _, s := range config.Conf.Servers {
		go func(s config.ServerInfo) {
			defer func() {
				if p := recover(); p != nil {
					Log.Debugf("Panic: %s on %s", p, s.ServerName)
				}
			}()
			osTypeChan <- detectOS(s)
		}(s)
	}

	var oses []osTypeInterface
	timeout := time.After(30 * time.Second)
	for i := 0; i < len(config.Conf.Servers); i++ {
		select {
		case res := <-osTypeChan:
			oses = append(oses, res)
			if 0 < len(res.getErrs()) {
				Log.Errorf("(%d/%d) Failed: %s, err: %s",
					i+1, len(config.Conf.Servers),
					res.getServerInfo().ServerName,
					res.getErrs())
			} else {
				Log.Infof("(%d/%d) Detected: %s: %s",
					i+1, len(config.Conf.Servers),
					res.getServerInfo().ServerName,
					res.getDistributionInfo())
			}
		case <-timeout:
			msg := "Timed out while detecting servers"
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
					Log.Errorf("(%d/%d) Timed out: %s",
						i+1, len(config.Conf.Servers),
						servername)
					i++
				}
			}
		}
	}

	for _, o := range oses {
		if len(o.getErrs()) == 0 {
			sshAbleOses = append(sshAbleOses, o)
		}
	}
	return
}

func detectContainerOSes() (actives []osTypeInterface) {
	Log.Info("Detecting OS of containers... ")
	osTypesChan := make(chan []osTypeInterface, len(servers))
	defer close(osTypesChan)
	for _, s := range servers {
		go func(s osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					Log.Debugf("Panic: %s on %s",
						p, s.getServerInfo().ServerName)
				}
			}()
			osTypesChan <- detectContainerOSesOnServer(s)
		}(s)
	}

	var oses []osTypeInterface
	timeout := time.After(30 * time.Second)
	for i := 0; i < len(servers); i++ {
		select {
		case res := <-osTypesChan:
			for _, osi := range res {
				sinfo := osi.getServerInfo()
				if 0 < len(osi.getErrs()) {
					Log.Errorf("Failed: %s err: %s", sinfo.ServerName, osi.getErrs())
					continue
				}
				oses = append(oses, res...)
				Log.Infof("Detected: %s@%s: %s",
					sinfo.Container.Name, sinfo.ServerName, osi.getDistributionInfo())
			}
		case <-timeout:
			msg := "Timed out while detecting containers"
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
					Log.Errorf("Timed out: %s", servername)

				}
			}
		}
	}
	for _, o := range oses {
		if len(o.getErrs()) == 0 {
			actives = append(actives, o)
		}
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

// CheckIfSudoNoPasswd checks whether vuls can sudo with nopassword via SSH
func CheckIfSudoNoPasswd(localLogger *logrus.Entry) error {
	timeoutSec := 1 * 15
	errs := parallelSSHExec(func(o osTypeInterface) error {
		return o.checkIfSudoNoPasswd()
	}, timeoutSec)

	if 0 < len(errs) {
		return fmt.Errorf(fmt.Sprintf("%s", errs))
	}
	return nil
}

// DetectPlatforms detects the platform of each servers.
func DetectPlatforms(localLogger *logrus.Entry) {
	errs := detectPlatforms()
	if 0 < len(errs) {
		// Only logging
		Log.Warnf("Failed to detect platforms. err: %v", errs)
	}
	for i, s := range servers {
		if s.getServerInfo().IsContainer() {
			Log.Infof("(%d/%d) %s on %s is running on %s",
				i+1, len(servers),
				s.getServerInfo().Container.Name,
				s.getServerInfo().ServerName,
				s.getPlatform().Name,
			)

		} else {
			Log.Infof("(%d/%d) %s is running on %s",
				i+1, len(servers),
				s.getServerInfo().ServerName,
				s.getPlatform().Name,
			)
		}
	}
	return
}

func detectPlatforms() []error {
	timeoutSec := 1 * 60
	return parallelSSHExec(func(o osTypeInterface) error {
		return o.detectPlatform()
	}, timeoutSec)
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
	timeoutSec := 120 * 60
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
