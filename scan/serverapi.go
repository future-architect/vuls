package scan

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

const (
	scannedViaRemote = "remote"
	scannedViaLocal  = "local"
	scannedViaPseudo = "pseudo"
)

var (
	errOSFamilyHeader      = xerrors.New("X-Vuls-OS-Family header is required")
	errOSReleaseHeader     = xerrors.New("X-Vuls-OS-Release header is required")
	errKernelVersionHeader = xerrors.New("X-Vuls-Kernel-Version header is required")
	errServerNameHeader    = xerrors.New("X-Vuls-Server-Name header is required")
)

var servers, errServers []osTypeInterface

// Base Interface
type osTypeInterface interface {
	setServerInfo(config.ServerInfo)
	getServerInfo() config.ServerInfo
	setDistro(string, string)
	getDistro() config.Distro
	detectPlatform()
	detectIPS()
	getPlatform() models.Platform

	checkScanMode() error
	checkDeps() error
	checkIfSudoNoPasswd() error

	preCure() error
	postScan() error
	scanWordPress() error
	scanLibraries() error
	scanPorts() error
	scanPackages() error
	convertToModel() models.ScanResult

	parseInstalledPackages(string) (models.Packages, models.SrcPackages, error)

	runningContainers() ([]config.Container, error)
	exitedContainers() ([]config.Container, error)
	allContainers() ([]config.Container, error)

	getErrs() []error
	setErrs([]error)
}

type Scanner struct {
	TimeoutSec     int
	ScanTimeoutSec int
	CacheDBPath    string

	Targets map[string]config.ServerInfo
}

func (s Scanner) Scan() error {
	util.Log.Info("Detecting Server/Container OS... ")
	if err := initServers(s.Targets, s.TimeoutSec); err != nil {
		return xerrors.Errorf("Failed to init servers. err: %w", err)
	}

	util.Log.Info("Checking Scan Modes... ")
	if err := checkScanModes(); err != nil {
		return xerrors.Errorf("Fix config.toml. err: %w", err)
	}

	util.Log.Info("Detecting Platforms... ")
	detectPlatform(s.TimeoutSec)

	util.Log.Info("Detecting IPS identifiers... ")
	detectIPS(s.TimeoutSec)

	if err := execScan(s.CacheDBPath, s.ScanTimeoutSec); err != nil {
		return xerrors.Errorf("Failed to scan. err: %w", err)
	}
	return nil
}

func (s Scanner) Configtest() error {
	util.Log.Info("Detecting Server/Container OS... ")
	if err := initServers(s.Targets, s.TimeoutSec); err != nil {
		return xerrors.Errorf("Failed to init servers. err: %w", err)
	}

	util.Log.Info("Checking Scan Modes...")
	if err := checkScanModes(); err != nil {
		return xerrors.Errorf("Fix config.toml. err: %w", err)
	}

	util.Log.Info("Checking dependencies...")
	checkDependencies(s.TimeoutSec)

	util.Log.Info("Checking sudo settings...")
	checkIfSudoNoPasswd(s.TimeoutSec)

	return nil
}

// Retry as it may stall on the first SSH connection
// https://github.com/future-architect/vuls/pull/753
func detectDebianWithRetry(c config.ServerInfo) (itsMe bool, deb osTypeInterface, err error) {
	type Response struct {
		itsMe bool
		deb   osTypeInterface
		err   error
	}
	resChan := make(chan Response, 1)
	go func(c config.ServerInfo) {
		itsMe, osType, fatalErr := detectDebian(c)
		resChan <- Response{itsMe, osType, fatalErr}
	}(c)

	timeout := time.After(time.Duration(3) * time.Second)
	select {
	case res := <-resChan:
		return res.itsMe, res.deb, res.err
	case <-timeout:
		time.Sleep(100 * time.Millisecond)
		return detectDebian(c)
	}
}

func detectOS(c config.ServerInfo) (osType osTypeInterface) {
	var itsMe bool
	var fatalErr error

	if itsMe, osType, _ = detectPseudo(c); itsMe {
		util.Log.Debugf("Pseudo")
		return
	}

	itsMe, osType, fatalErr = detectDebianWithRetry(c)
	if fatalErr != nil {
		osType.setErrs([]error{
			xerrors.Errorf("Failed to detect OS: %w", fatalErr)})
		return
	}

	if itsMe {
		util.Log.Debugf("Debian like Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectRedhat(c); itsMe {
		util.Log.Debugf("Redhat like Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectSUSE(c); itsMe {
		util.Log.Debugf("SUSE Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectFreebsd(c); itsMe {
		util.Log.Debugf("FreeBSD. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectAlpine(c); itsMe {
		util.Log.Debugf("Alpine. Host: %s:%s", c.Host, c.Port)
		return
	}

	//TODO darwin https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/darwin.rb
	osType.setErrs([]error{xerrors.New("Unknown OS Type")})
	return
}

// PrintSSHableServerNames print SSH-able servernames
func PrintSSHableServerNames() bool {
	if len(servers) == 0 {
		util.Log.Error("No scannable servers")
		return false
	}
	util.Log.Info("Scannable servers are below...")
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
	return true
}

// initServers detect the kind of OS distribution of target servers
func initServers(targets map[string]config.ServerInfo, timeoutSec int) error {
	hosts, errHosts := detectServerOSes(targets, timeoutSec)
	if len(hosts) == 0 {
		return xerrors.New("No scannable host OS")
	}
	containers, errContainers := detectContainerOSes(hosts, timeoutSec)

	// set to pkg global variable
	for _, host := range hosts {
		if !host.getServerInfo().ContainersOnly {
			servers = append(servers, host)
		}
	}
	servers = append(servers, containers...)
	errServers = append(errHosts, errContainers...)

	if len(servers) == 0 {
		return xerrors.New("No scannable servers")
	}
	return nil
}

func detectServerOSes(targets map[string]config.ServerInfo, timeoutSec int) (servers, errServers []osTypeInterface) {
	util.Log.Info("Detecting OS of servers... ")
	osTypeChan := make(chan osTypeInterface, len(targets))
	defer close(osTypeChan)
	for _, s := range targets {
		go func(s config.ServerInfo) {
			defer func() {
				if p := recover(); p != nil {
					util.Log.Debugf("Panic: %s on %s", p, s.ServerName)
				}
			}()
			osTypeChan <- detectOS(s)
		}(s)
	}

	timeout := time.After(time.Duration(timeoutSec) * time.Second)
	for i := 0; i < len(targets); i++ {
		select {
		case res := <-osTypeChan:
			if 0 < len(res.getErrs()) {
				errServers = append(errServers, res)
				util.Log.Errorf("(%d/%d) Failed: %s, err: %+v",
					i+1, len(targets),
					res.getServerInfo().ServerName,
					res.getErrs())
			} else {
				servers = append(servers, res)
				util.Log.Infof("(%d/%d) Detected: %s: %s",
					i+1, len(targets),
					res.getServerInfo().ServerName,
					res.getDistro())
			}
		case <-timeout:
			msg := "Timed out while detecting servers"
			util.Log.Error(msg)
			for servername, sInfo := range targets {
				found := false
				for _, o := range append(servers, errServers...) {
					if servername == o.getServerInfo().ServerName {
						found = true
						break
					}
				}
				if !found {
					u := &unknown{}
					u.setServerInfo(sInfo)
					u.setErrs([]error{xerrors.New("Timed out")})
					errServers = append(errServers, u)
					util.Log.Errorf("(%d/%d) Timed out: %s", i+1, len(targets), servername)
				}
			}
		}
	}
	return
}

func detectContainerOSes(hosts []osTypeInterface, timeoutSec int) (actives, inactives []osTypeInterface) {
	util.Log.Info("Detecting OS of containers... ")
	osTypesChan := make(chan []osTypeInterface, len(hosts))
	defer close(osTypesChan)
	for _, s := range hosts {
		go func(s osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					util.Log.Debugf("Panic: %s on %s",
						p, s.getServerInfo().GetServerName())
				}
			}()
			osTypesChan <- detectContainerOSesOnServer(s)
		}(s)
	}

	timeout := time.After(time.Duration(timeoutSec) * time.Second)
	for i := 0; i < len(hosts); i++ {
		select {
		case res := <-osTypesChan:
			for _, osi := range res {
				sinfo := osi.getServerInfo()
				if 0 < len(osi.getErrs()) {
					inactives = append(inactives, osi)
					util.Log.Errorf("Failed: %s err: %+v", sinfo.ServerName, osi.getErrs())
					continue
				}
				actives = append(actives, osi)
				util.Log.Infof("Detected: %s@%s: %s",
					sinfo.Container.Name, sinfo.ServerName, osi.getDistro())
			}
		case <-timeout:
			util.Log.Error("Some containers timed out")
		}
	}
	return
}

func detectContainerOSesOnServer(containerHost osTypeInterface) (oses []osTypeInterface) {
	containerHostInfo := containerHost.getServerInfo()
	if len(containerHostInfo.ContainersIncluded) == 0 {
		return
	}

	running, err := containerHost.runningContainers()
	if err != nil {
		containerHost.setErrs([]error{xerrors.Errorf(
			"Failed to get running containers on %s. err: %w",
			containerHost.getServerInfo().ServerName, err)})
		return append(oses, containerHost)
	}

	if containerHostInfo.ContainersIncluded[0] == "${running}" {
		for _, containerInfo := range running {
			found := false
			for _, ex := range containerHost.getServerInfo().ContainersExcluded {
				if containerInfo.Name == ex || containerInfo.ContainerID == ex {
					found = true
				}
			}
			if found {
				continue
			}

			copied := containerHostInfo
			copied.SetContainer(config.Container{
				ContainerID: containerInfo.ContainerID,
				Name:        containerInfo.Name,
				Image:       containerInfo.Image,
			})
			os := detectOS(copied)
			oses = append(oses, os)
		}
		return oses
	}

	exitedContainers, err := containerHost.exitedContainers()
	if err != nil {
		containerHost.setErrs([]error{xerrors.Errorf(
			"Failed to get exited containers on %s. err: %w",
			containerHost.getServerInfo().ServerName, err)})
		return append(oses, containerHost)
	}

	var exited, unknown []string
	for _, container := range containerHostInfo.ContainersIncluded {
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
		containerHost.setErrs([]error{xerrors.Errorf(
			"Some containers on %s are exited or unknown. exited: %s, unknown: %s",
			containerHost.getServerInfo().ServerName, exited, unknown)})
		return append(oses, containerHost)
	}
	return oses
}

// checkScanModes checks scan mode
func checkScanModes() error {
	for _, s := range servers {
		if err := s.checkScanMode(); err != nil {
			return xerrors.Errorf("servers.%s.scanMode err: %w",
				s.getServerInfo().GetServerName(), err)
		}
	}
	return nil
}

// checkDependencies checks dependencies are installed on target servers.
func checkDependencies(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		return o.checkDeps()
	}, timeoutSec)
	return
}

// checkIfSudoNoPasswd checks whether vuls can sudo with nopassword via SSH
func checkIfSudoNoPasswd(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		return o.checkIfSudoNoPasswd()
	}, timeoutSec)
	return
}

// detectPlatform detects the platform of each servers.
func detectPlatform(timeoutSec int) {
	execDetectPlatform(timeoutSec)
	for i, s := range servers {
		if s.getServerInfo().IsContainer() {
			util.Log.Infof("(%d/%d) %s on %s is running on %s",
				i+1, len(servers),
				s.getServerInfo().Container.Name,
				s.getServerInfo().ServerName,
				s.getPlatform().Name,
			)

		} else {
			util.Log.Infof("(%d/%d) %s is running on %s",
				i+1, len(servers),
				s.getServerInfo().ServerName,
				s.getPlatform().Name,
			)
		}
	}
	return
}

func execDetectPlatform(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		o.detectPlatform()
		// Logging only if platform can not be specified
		return nil
	}, timeoutSec)
	return
}

// detectIPS detects the IPS of each servers.
func detectIPS(timeoutSec int) {
	execDetectIPS(timeoutSec)
	for i, s := range servers {
		if !s.getServerInfo().IsContainer() {
			util.Log.Infof("(%d/%d) %s has %d IPS integration",
				i+1, len(servers),
				s.getServerInfo().ServerName,
				len(s.getServerInfo().IPSIdentifiers),
			)
		}
	}
}

func execDetectIPS(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		o.detectIPS()
		// Logging only if IPS can not be specified
		return nil
	}, timeoutSec)
}

// execScan scan
func execScan(cacheDBPath string, timeoutSec int) error {
	if len(servers) == 0 {
		return xerrors.New("No server defined. Check the configuration")
	}

	if err := setupChangelogCache(cacheDBPath); err != nil {
		return err
	}
	defer func() {
		if cache.DB != nil {
			cache.DB.Close()
		}
	}()

	scannedAt := time.Now()
	dir, err := EnsureResultDir(scannedAt)
	if err != nil {
		return err
	}

	results, err := GetScanResults(scannedAt, timeoutSec)
	if err != nil {
		return err
	}

	for i, r := range results {
		if s, ok := config.Conf.Servers[r.ServerName]; ok {
			results[i] = r.ClearFields(s.IgnoredJSONKeys)
		}
	}

	return writeScanResults(dir, results)
}

// ViaHTTP scans servers by HTTP header and body
func ViaHTTP(header http.Header, body string, toLocalFile bool) (models.ScanResult, error) {
	family := header.Get("X-Vuls-OS-Family")
	if family == "" {
		return models.ScanResult{}, errOSFamilyHeader
	}

	release := header.Get("X-Vuls-OS-Release")
	if release == "" {
		return models.ScanResult{}, errOSReleaseHeader
	}

	kernelRelease := header.Get("X-Vuls-Kernel-Release")
	if kernelRelease == "" {
		util.Log.Warn("If X-Vuls-Kernel-Release is not specified, there is a possibility of false detection")
	}

	kernelVersion := header.Get("X-Vuls-Kernel-Version")
	if family == constant.Debian && kernelVersion == "" {
		return models.ScanResult{}, errKernelVersionHeader
	}

	serverName := header.Get("X-Vuls-Server-Name")
	if toLocalFile && serverName == "" {
		return models.ScanResult{}, errServerNameHeader
	}

	distro := config.Distro{
		Family:  family,
		Release: release,
	}

	kernel := models.Kernel{
		Release: kernelRelease,
		Version: kernelVersion,
	}
	base := base{
		Distro: distro,
		osPackages: osPackages{
			Kernel: kernel,
		},
		log: util.Log,
	}

	var osType osTypeInterface
	switch family {
	case constant.Debian, constant.Ubuntu:
		osType = &debian{base: base}
	case constant.RedHat:
		osType = &rhel{
			redhatBase: redhatBase{base: base},
		}
	case constant.CentOS:
		osType = &centos{
			redhatBase: redhatBase{base: base},
		}
	case constant.Oracle:
		osType = &oracle{
			redhatBase: redhatBase{base: base},
		}
	case constant.Amazon:
		osType = &amazon{
			redhatBase: redhatBase{base: base},
		}
	default:
		return models.ScanResult{}, xerrors.Errorf("Server mode for %s is not implemented yet", family)
	}

	installedPackages, srcPackages, err := osType.parseInstalledPackages(body)
	if err != nil {
		return models.ScanResult{}, err
	}

	result := models.ScanResult{
		ServerName: serverName,
		Family:     family,
		Release:    release,
		RunningKernel: models.Kernel{
			Release: kernelRelease,
			Version: kernelVersion,
		},
		Packages:    installedPackages,
		SrcPackages: srcPackages,
		ScannedCves: models.VulnInfos{},
	}

	return result, nil
}

func setupChangelogCache(path string) error {
	needToSetupCache := false
	for _, s := range servers {
		switch s.getDistro().Family {
		case constant.Raspbian:
			needToSetupCache = true
			break
		case constant.Ubuntu, constant.Debian:
			//TODO changelog cache for RedHat, Oracle, Amazon, CentOS is not implemented yet.
			if s.getServerInfo().Mode.IsDeep() {
				needToSetupCache = true
			}
			break
		}
	}
	if needToSetupCache {
		if err := cache.SetupBolt(path, util.Log); err != nil {
			return err
		}
	}
	return nil
}

// GetScanResults returns ScanResults from
func GetScanResults(scannedAt time.Time, timeoutSec int) (results models.ScanResults, err error) {
	parallelExec(func(o osTypeInterface) (err error) {
		if o.getServerInfo().Module.IsScanOSPkg() {
			if err = o.preCure(); err != nil {
				return err
			}
			if err = o.scanPackages(); err != nil {
				return err
			}
			if err = o.postScan(); err != nil {
				return err
			}
		}
		if o.getServerInfo().Module.IsScanPort() {
			if err = o.scanPorts(); err != nil {
				return xerrors.Errorf("Failed to scan Ports: %w", err)
			}
		}
		if o.getServerInfo().Module.IsScanWordPress() {
			if err = o.scanWordPress(); err != nil {
				return xerrors.Errorf("Failed to scan WordPress: %w", err)
			}
		}
		if o.getServerInfo().Module.IsScanLockFile() {
			if err = o.scanLibraries(); err != nil {
				return xerrors.Errorf("Failed to scan Library: %w", err)
			}
		}
		return nil
	}, timeoutSec)

	hostname, _ := os.Hostname()
	ipv4s, ipv6s, err := util.IP()
	if err != nil {
		util.Log.Errorf("Failed to fetch scannedIPs. err: %+v", err)
	}

	for _, s := range append(servers, errServers...) {
		r := s.convertToModel()
		checkEOL(&r)
		r.ScannedAt = scannedAt
		r.ScannedVersion = config.Version
		r.ScannedRevision = config.Revision
		r.ScannedBy = hostname
		r.ScannedIPv4Addrs = ipv4s
		r.ScannedIPv6Addrs = ipv6s
		r.Config.Scan = config.Conf
		results = append(results, r)

		if 0 < len(r.Warnings) {
			util.Log.Warnf("Some warnings occurred during scanning on %s. Please fix the warnings to get a useful information. Execute configtest subcommand before scanning to know the cause of the warnings. warnings: %v",
				r.ServerName, r.Warnings)
		}
	}
	return results, nil
}

func checkEOL(r *models.ScanResult) {
	switch r.Family {
	case constant.ServerTypePseudo, constant.Raspbian:
		return
	}

	eol, found := config.GetEOL(r.Family, r.Release)
	if !found {
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("Failed to check EOL. Register the issue to https://github.com/future-architect/vuls/issues with the information in `Family: %s Release: %s`",
				r.Family, r.Release))
		return
	}

	now := time.Now()
	if eol.IsStandardSupportEnded(now) {
		r.Warnings = append(r.Warnings, "Standard OS support is EOL(End-of-Life). Purchase extended support if available or Upgrading your OS is strongly recommended.")
		if eol.ExtendedSupportUntil.IsZero() {
			return
		}
		if !eol.IsExtendedSuppportEnded(now) {
			r.Warnings = append(r.Warnings,
				fmt.Sprintf("Extended support available until %s. Check the vendor site.",
					eol.ExtendedSupportUntil.Format("2006-01-02")))
		} else {
			r.Warnings = append(r.Warnings,
				"Extended support is also EOL. There are many Vulnerabilities that are not detected, Upgrading your OS strongly recommended.")
		}
	} else if !eol.StandardSupportUntil.IsZero() &&
		now.AddDate(0, 3, 0).After(eol.StandardSupportUntil) {
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("Standard OS support will be end in 3 months. EOL date: %s",
				eol.StandardSupportUntil.Format("2006-01-02")))
	}
}
