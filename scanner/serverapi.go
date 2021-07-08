package scanner

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
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

	setLogger(logging.Logger)
	getErrs() []error
	setErrs([]error)
}

// Scanner has functions for scan
type Scanner struct {
	ResultsDir     string
	TimeoutSec     int
	ScanTimeoutSec int
	CacheDBPath    string
	Debug          bool
	LogToFile      bool
	LogDir         string
	Quiet          bool
	DetectIPS      bool

	Targets map[string]config.ServerInfo
}

// Scan execute scan
func (s Scanner) Scan() error {
	logging.Log.Info("Detecting Server/Container OS... ")
	if err := s.initServers(); err != nil {
		return xerrors.Errorf("Failed to init servers. err: %w", err)
	}

	logging.Log.Info("Checking Scan Modes... ")
	if err := s.checkScanModes(); err != nil {
		return xerrors.Errorf("Fix config.toml. err: %w", err)
	}

	logging.Log.Info("Detecting Platforms... ")
	s.detectPlatform()

	if s.DetectIPS {
		logging.Log.Info("Detecting IPS identifiers... ")
		s.detectIPS()
	}

	if err := s.execScan(); err != nil {
		return xerrors.Errorf("Failed to scan. err: %w", err)
	}
	return nil
}

// Configtest checks if the server is scannable.
func (s Scanner) Configtest() error {
	logging.Log.Info("Detecting Server/Container OS... ")
	if err := s.initServers(); err != nil {
		return xerrors.Errorf("Failed to init servers. err: %w", err)
	}

	logging.Log.Info("Checking Scan Modes...")
	if err := s.checkScanModes(); err != nil {
		return xerrors.Errorf("Fix config.toml. err: %w", err)
	}

	logging.Log.Info("Checking dependencies...")
	s.checkDependencies()

	logging.Log.Info("Checking sudo settings...")
	s.checkIfSudoNoPasswd()

	logging.Log.Info("It can be scanned with fast scan mode even if warn or err messages are displayed due to lack of dependent packages or sudo settings in fast-root or deep scan mode")

	if len(servers) == 0 {
		return xerrors.Errorf("No scannable servers")
	}

	logging.Log.Info("Scannable servers are below...")
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
	return nil
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
		logging.Log.Warn("If X-Vuls-Kernel-Release is not specified, there is a possibility of false detection")
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
	installedPackages, srcPackages, err := ParseInstalledPkgs(distro, kernel, body)
	if err != nil {
		return models.ScanResult{}, err
	}

	return models.ScanResult{
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
	}, nil
}

// ParseInstalledPkgs parses installed pkgs line
func ParseInstalledPkgs(distro config.Distro, kernel models.Kernel, pkgList string) (models.Packages, models.SrcPackages, error) {
	base := base{
		Distro: distro,
		osPackages: osPackages{
			Kernel: kernel,
		},
		log: logging.Log,
	}

	var osType osTypeInterface
	switch distro.Family {
	case constant.Debian, constant.Ubuntu, constant.Raspbian:
		osType = &debian{base: base}
	case constant.RedHat:
		osType = &rhel{redhatBase: redhatBase{base: base}}
	case constant.CentOS:
		osType = &centos{redhatBase: redhatBase{base: base}}
	case constant.Rocky:
		osType = &rocky{redhatBase: redhatBase{base: base}}
	case constant.Oracle:
		osType = &oracle{redhatBase: redhatBase{base: base}}
	case constant.Amazon:
		osType = &amazon{redhatBase: redhatBase{base: base}}
	default:
		return models.Packages{}, models.SrcPackages{}, xerrors.Errorf("Server mode for %s is not implemented yet", base.Distro.Family)
	}

	return osType.parseInstalledPackages(pkgList)
}

// initServers detect the kind of OS distribution of target servers
func (s Scanner) initServers() error {
	hosts, errHosts := s.detectServerOSes()
	if len(hosts) == 0 {
		return xerrors.New("No scannable host OS")
	}

	// to generate random color for logging
	rand.Seed(time.Now().UnixNano())
	for _, srv := range hosts {
		srv.setLogger(logging.NewCustomLogger(s.Debug, s.Quiet, s.LogToFile, s.LogDir, config.Colors[rand.Intn(len(config.Colors))], srv.getServerInfo().GetServerName()))
	}

	containers, errContainers := s.detectContainerOSes(hosts)
	for _, srv := range containers {
		srv.setLogger(logging.NewCustomLogger(s.Debug, s.Quiet, s.LogToFile, s.LogDir, config.Colors[rand.Intn(len(config.Colors))], srv.getServerInfo().GetServerName()))
	}

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

func (s Scanner) detectServerOSes() (servers, errServers []osTypeInterface) {
	logging.Log.Info("Detecting OS of servers... ")
	osTypeChan := make(chan osTypeInterface, len(s.Targets))
	defer close(osTypeChan)
	for _, target := range s.Targets {
		go func(srv config.ServerInfo) {
			defer func() {
				if p := recover(); p != nil {
					logging.Log.Debugf("Panic: %s on %s", p, srv.ServerName)
				}
			}()
			osTypeChan <- s.detectOS(srv)
		}(target)
	}

	timeout := time.After(time.Duration(s.TimeoutSec) * time.Second)
	for i := 0; i < len(s.Targets); i++ {
		select {
		case res := <-osTypeChan:
			if 0 < len(res.getErrs()) {
				errServers = append(errServers, res)
				logging.Log.Errorf("(%d/%d) Failed: %s, err: %+v",
					i+1, len(s.Targets), res.getServerInfo().ServerName, res.getErrs())
			} else {
				servers = append(servers, res)
				logging.Log.Infof("(%d/%d) Detected: %s: %s",
					i+1, len(s.Targets), res.getServerInfo().ServerName, res.getDistro())
			}
		case <-timeout:
			msg := "Timed out while detecting servers"
			logging.Log.Error(msg)
			for servername, sInfo := range s.Targets {
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
					logging.Log.Errorf("(%d/%d) Timed out: %s", i+1, len(s.Targets), servername)
				}
			}
		}
	}
	return
}

func (s Scanner) detectContainerOSes(hosts []osTypeInterface) (actives, inactives []osTypeInterface) {
	logging.Log.Info("Detecting OS of containers... ")
	osTypesChan := make(chan []osTypeInterface, len(hosts))
	defer close(osTypesChan)
	for _, host := range hosts {
		go func(h osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					logging.Log.Debugf("Panic: %s on %s",
						p, h.getServerInfo().GetServerName())
				}
			}()
			osTypesChan <- s.detectContainerOSesOnServer(h)
		}(host)
	}

	timeout := time.After(time.Duration(s.TimeoutSec) * time.Second)
	for i := 0; i < len(hosts); i++ {
		select {
		case res := <-osTypesChan:
			for _, osi := range res {
				sinfo := osi.getServerInfo()
				if 0 < len(osi.getErrs()) {
					inactives = append(inactives, osi)
					logging.Log.Errorf("Failed: %s err: %+v", sinfo.ServerName, osi.getErrs())
					continue
				}
				actives = append(actives, osi)
				logging.Log.Infof("Detected: %s@%s: %s",
					sinfo.Container.Name, sinfo.ServerName, osi.getDistro())
			}
		case <-timeout:
			logging.Log.Error("Some containers timed out")
		}
	}
	return
}

func (s Scanner) detectContainerOSesOnServer(containerHost osTypeInterface) (oses []osTypeInterface) {
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
			os := s.detectOS(copied)
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
				os := s.detectOS(copied)
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

func (s Scanner) detectOS(c config.ServerInfo) (osType osTypeInterface) {
	var itsMe bool
	var fatalErr error

	if itsMe, osType, _ = detectPseudo(c); itsMe {
		return
	}

	itsMe, osType, fatalErr = s.detectDebianWithRetry(c)
	if fatalErr != nil {
		osType.setErrs([]error{
			xerrors.Errorf("Failed to detect OS: %w", fatalErr)})
		return
	}

	if itsMe {
		logging.Log.Debugf("Debian like Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectRedhat(c); itsMe {
		logging.Log.Debugf("Redhat like Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectSUSE(c); itsMe {
		logging.Log.Debugf("SUSE Linux. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectFreebsd(c); itsMe {
		logging.Log.Debugf("FreeBSD. Host: %s:%s", c.Host, c.Port)
		return
	}

	if itsMe, osType = detectAlpine(c); itsMe {
		logging.Log.Debugf("Alpine. Host: %s:%s", c.Host, c.Port)
		return
	}

	//TODO darwin https://github.com/mizzy/specinfra/blob/master/lib/specinfra/helper/detect_os/darwin.rb
	osType.setErrs([]error{xerrors.New("Unknown OS Type")})
	return
}

// Retry as it may stall on the first SSH connection
// https://github.com/future-architect/vuls/pull/753
func (s Scanner) detectDebianWithRetry(c config.ServerInfo) (itsMe bool, deb osTypeInterface, err error) {
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

// checkScanModes checks scan mode
func (s Scanner) checkScanModes() error {
	for _, s := range servers {
		if err := s.checkScanMode(); err != nil {
			return xerrors.Errorf("servers.%s.scanMode err: %w",
				s.getServerInfo().GetServerName(), err)
		}
	}
	return nil
}

// checkDependencies checks dependencies are installed on target servers.
func (s Scanner) checkDependencies() {
	parallelExec(func(o osTypeInterface) error {
		return o.checkDeps()
	}, s.TimeoutSec)
	return
}

// checkIfSudoNoPasswd checks whether vuls can sudo with nopassword via SSH
func (s Scanner) checkIfSudoNoPasswd() {
	parallelExec(func(o osTypeInterface) error {
		return o.checkIfSudoNoPasswd()
	}, s.TimeoutSec)
	return
}

// detectPlatform detects the platform of each servers.
func (s Scanner) detectPlatform() {
	parallelExec(func(o osTypeInterface) error {
		o.detectPlatform()
		// Logging only if platform can not be specified
		return nil
	}, s.TimeoutSec)

	for i, s := range servers {
		if s.getServerInfo().IsContainer() {
			logging.Log.Infof("(%d/%d) %s on %s is running on %s",
				i+1, len(servers),
				s.getServerInfo().Container.Name,
				s.getServerInfo().ServerName,
				s.getPlatform().Name,
			)

		} else {
			logging.Log.Infof("(%d/%d) %s is running on %s",
				i+1, len(servers),
				s.getServerInfo().ServerName,
				s.getPlatform().Name,
			)
		}
	}
	return
}

// detectIPS detects the IPS of each servers.
func (s Scanner) detectIPS() {
	parallelExec(func(o osTypeInterface) error {
		o.detectIPS()
		// Logging only if IPS can not be specified
		return nil
	}, s.TimeoutSec)

	for i, s := range servers {
		if !s.getServerInfo().IsContainer() {
			logging.Log.Infof("(%d/%d) %s has %d IPS integration",
				i+1, len(servers),
				s.getServerInfo().ServerName,
				len(s.getServerInfo().IPSIdentifiers),
			)
		}
	}
}

// execScan scan
func (s Scanner) execScan() error {
	if len(servers) == 0 {
		return xerrors.New("No server defined. Check the configuration")
	}

	if err := s.setupChangelogCache(); err != nil {
		return err
	}
	defer func() {
		if cache.DB != nil {
			cache.DB.Close()
		}
	}()

	scannedAt := time.Now()
	dir, err := EnsureResultDir(s.ResultsDir, scannedAt)
	if err != nil {
		return err
	}

	results, err := s.getScanResults(scannedAt)
	if err != nil {
		return err
	}

	for i, r := range results {
		if server, ok := s.Targets[r.ServerName]; ok {
			results[i] = r.ClearFields(server.IgnoredJSONKeys)
		}
	}

	return writeScanResults(dir, results)
}

func (s Scanner) setupChangelogCache() error {
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
		if err := cache.SetupBolt(s.CacheDBPath, logging.Log); err != nil {
			return err
		}
	}
	return nil
}

// getScanResults returns ScanResults
func (s Scanner) getScanResults(scannedAt time.Time) (results models.ScanResults, err error) {
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
	}, s.ScanTimeoutSec)

	hostname, _ := os.Hostname()
	ipv4s, ipv6s, err := util.IP()
	if err != nil {
		logging.Log.Warnf("Failed to get scannedIPs. err: %+v", err)
	}

	for _, s := range append(servers, errServers...) {
		r := s.convertToModel()
		r.CheckEOL()
		r.ScannedAt = scannedAt
		r.ScannedVersion = config.Version
		r.ScannedRevision = config.Revision
		r.ScannedBy = hostname
		r.ScannedIPv4Addrs = ipv4s
		r.ScannedIPv6Addrs = ipv6s
		r.Config.Scan = config.Conf
		results = append(results, r)

		if 0 < len(r.Warnings) {
			logging.Log.Warnf("Some warnings occurred during scanning on %s. Please fix the warnings to get a useful information. Execute configtest subcommand before scanning to know the cause of the warnings. warnings: %v",
				r.ServerName, r.Warnings)
		}
	}
	return results, nil
}
