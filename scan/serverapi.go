/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
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

// Base Interface of redhat, debian, freebsd
type osTypeInterface interface {
	setServerInfo(config.ServerInfo)
	getServerInfo() config.ServerInfo
	setDistro(string, string)
	getDistro() config.Distro
	detectPlatform()
	detectIPSs()
	getPlatform() models.Platform

	checkScanMode() error
	checkDeps() error
	checkIfSudoNoPasswd() error

	preCure() error
	postScan() error
	scanWordPress() error
	scanLibraries() error
	scanPackages() error
	convertToModel() models.ScanResult

	parseInstalledPackages(string) (models.Packages, models.SrcPackages, error)

	runningContainers() ([]config.Container, error)
	exitedContainers() ([]config.Container, error)
	allContainers() ([]config.Container, error)

	getErrs() []error
	setErrs([]error)
}

// osPackages is included by base struct
type osPackages struct {
	// installed packages
	Packages models.Packages

	// installed source packages (Debian based only)
	SrcPackages models.SrcPackages

	// unsecure packages
	VulnInfos models.VulnInfos

	// kernel information
	Kernel models.Kernel
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

	itsMe, osType, fatalErr = detectContainerImage(c)
	if fatalErr != nil {
		osType.setErrs(
			[]error{xerrors.Errorf("Failed to detect OS: %w", fatalErr)},
		)
		return
	}
	if itsMe {
		util.Log.Debugf("Container")
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

func needScans() (needBaseServer, scanContainer, scanImage bool) {
	scanContainer = true
	scanImage = true
	if !config.Conf.ContainersOnly && !config.Conf.ImagesOnly {
		needBaseServer = true
	}

	if config.Conf.ImagesOnly && !config.Conf.ContainersOnly {
		scanContainer = false
	}

	if config.Conf.ContainersOnly && !config.Conf.ImagesOnly {
		scanImage = false
	}
	return needBaseServer, scanContainer, scanImage
}

// InitServers detect the kind of OS distribution of target servers
func InitServers(timeoutSec int) error {
	needBaseServers, scanContainer, scanImage := needScans()

	// use global servers, errServers when scan containers and images
	servers, errServers = detectServerOSes(timeoutSec)
	if len(servers) == 0 {
		return xerrors.New("No scannable base servers")
	}

	// scan additional servers
	var actives, inactives []osTypeInterface
	if scanImage {
		oks, errs := detectImageOSes(timeoutSec)
		actives = append(actives, oks...)
		inactives = append(inactives, errs...)
	}
	if scanContainer {
		oks, errs := detectContainerOSes(timeoutSec)
		actives = append(actives, oks...)
		inactives = append(inactives, errs...)
	}

	if needBaseServers {
		servers = append(servers, actives...)
		errServers = append(errServers, inactives...)
	} else {
		servers = actives
		errServers = inactives
	}

	if len(servers) == 0 {
		return xerrors.New("No scannable servers")
	}
	return nil
}

func detectServerOSes(timeoutSec int) (servers, errServers []osTypeInterface) {
	util.Log.Info("Detecting OS of servers... ")
	osTypeChan := make(chan osTypeInterface, len(config.Conf.Servers))
	defer close(osTypeChan)
	for _, s := range config.Conf.Servers {
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
	for i := 0; i < len(config.Conf.Servers); i++ {
		select {
		case res := <-osTypeChan:
			if 0 < len(res.getErrs()) {
				errServers = append(errServers, res)
				util.Log.Errorf("(%d/%d) Failed: %s, err: %+v",
					i+1, len(config.Conf.Servers),
					res.getServerInfo().ServerName,
					res.getErrs())
			} else {
				servers = append(servers, res)
				util.Log.Infof("(%d/%d) Detected: %s: %s",
					i+1, len(config.Conf.Servers),
					res.getServerInfo().ServerName,
					res.getDistro())
			}
		case <-timeout:
			msg := "Timed out while detecting servers"
			util.Log.Error(msg)
			for servername, sInfo := range config.Conf.Servers {
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
					u.setErrs([]error{
						xerrors.New("Timed out"),
					})
					errServers = append(errServers, u)
					util.Log.Errorf("(%d/%d) Timed out: %s",
						i+1, len(config.Conf.Servers),
						servername)
					i++
				}
			}
		}
	}
	return
}

func detectContainerOSes(timeoutSec int) (actives, inactives []osTypeInterface) {
	util.Log.Info("Detecting OS of containers... ")
	osTypesChan := make(chan []osTypeInterface, len(servers))
	defer close(osTypesChan)
	for _, s := range servers {
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
	for i := 0; i < len(servers); i++ {
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
			msg := "Timed out while detecting containers"
			util.Log.Error(msg)
			for servername, sInfo := range config.Conf.Servers {
				found := false
				for _, o := range append(actives, inactives...) {
					if servername == o.getServerInfo().ServerName {
						found = true
						break
					}
				}
				if !found {
					u := &unknown{}
					u.setServerInfo(sInfo)
					u.setErrs([]error{
						xerrors.New("Timed out"),
					})
					inactives = append(inactives)
					util.Log.Errorf("Timed out: %s", servername)
				}
			}
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

func detectImageOSes(timeoutSec int) (actives, inactives []osTypeInterface) {
	util.Log.Info("Detecting OS of static containers... ")
	osTypesChan := make(chan []osTypeInterface, len(servers))
	defer close(osTypesChan)
	for _, s := range servers {
		go func(s osTypeInterface) {
			defer func() {
				if p := recover(); p != nil {
					util.Log.Debugf("Panic: %s on %s",
						p, s.getServerInfo().GetServerName())
				}
			}()
			osTypesChan <- detectImageOSesOnServer(s)
		}(s)
	}

	timeout := time.After(time.Duration(timeoutSec) * time.Second)
	for i := 0; i < len(servers); i++ {
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
					sinfo.Image.Name, sinfo.ServerName, osi.getDistro())
			}
		case <-timeout:
			msg := "Timed out while detecting static containers"
			util.Log.Error(msg)
			for servername, sInfo := range config.Conf.Servers {
				found := false
				for _, o := range append(actives, inactives...) {
					if servername == o.getServerInfo().ServerName {
						found = true
						break
					}
				}
				if !found {
					u := &unknown{}
					u.setServerInfo(sInfo)
					u.setErrs([]error{
						xerrors.New("Timed out"),
					})
					inactives = append(inactives)
					util.Log.Errorf("Timed out: %s", servername)
				}
			}
		}
	}
	return
}

func detectImageOSesOnServer(containerHost osTypeInterface) (oses []osTypeInterface) {
	containerHostInfo := containerHost.getServerInfo()
	if len(containerHostInfo.Images) == 0 {
		return
	}

	for idx, containerConf := range containerHostInfo.Images {
		copied := containerHostInfo
		// change servername for original
		copied.ServerName = fmt.Sprintf("%s:%s@%s", idx, containerConf.Tag, containerHostInfo.ServerName)
		copied.Image = containerConf
		copied.Type = ""
		os := detectOS(copied)
		oses = append(oses, os)
	}
	return oses
}

// CheckScanModes checks scan mode
func CheckScanModes() error {
	for _, s := range servers {
		if err := s.checkScanMode(); err != nil {
			return xerrors.Errorf("servers.%s.scanMode err: %w",
				s.getServerInfo().GetServerName(), err)
		}
	}
	return nil
}

// CheckDependencies checks dependencies are installed on target servers.
func CheckDependencies(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		return o.checkDeps()
	}, timeoutSec)
	return
}

// CheckIfSudoNoPasswd checks whether vuls can sudo with nopassword via SSH
func CheckIfSudoNoPasswd(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		return o.checkIfSudoNoPasswd()
	}, timeoutSec)
	return
}

// DetectPlatforms detects the platform of each servers.
func DetectPlatforms(timeoutSec int) {
	detectPlatforms(timeoutSec)
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

func detectPlatforms(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		o.detectPlatform()
		// Logging only if platform can not be specified
		return nil
	}, timeoutSec)
	return
}

// DetectIPSs detects the IPS of each servers.
func DetectIPSs(timeoutSec int) {
	detectIPSs(timeoutSec)
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

func detectIPSs(timeoutSec int) {
	parallelExec(func(o osTypeInterface) error {
		o.detectIPSs()
		// Logging only if IPS can not be specified
		return nil
	}, timeoutSec)
}

// Scan scan
func Scan(timeoutSec int) error {
	if len(servers) == 0 {
		return xerrors.New("No server defined. Check the configuration")
	}

	if err := setupChangelogCache(); err != nil {
		return err
	}
	defer func() {
		if cache.DB != nil {
			cache.DB.Close()
		}
	}()

	util.Log.Info("Scanning vulnerable OS packages...")
	scannedAt := time.Now()
	dir, err := EnsureResultDir(scannedAt)
	if err != nil {
		return err
	}
	return scanVulns(dir, scannedAt, timeoutSec)
}

// ViaHTTP scans servers by HTTP header and body
func ViaHTTP(header http.Header, body string) (models.ScanResult, error) {
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
	if family == config.Debian && kernelVersion == "" {
		return models.ScanResult{}, errKernelVersionHeader
	}

	serverName := header.Get("X-Vuls-Server-Name")
	if config.Conf.ToLocalFile && serverName == "" {
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
	case config.Debian, config.Ubuntu:
		osType = &debian{base: base}
	case config.RedHat:
		osType = &rhel{
			redhatBase: redhatBase{base: base},
		}
	case config.CentOS:
		osType = &centos{
			redhatBase: redhatBase{base: base},
		}
	case config.Amazon:
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

func setupChangelogCache() error {
	needToSetupCache := false
	for _, s := range servers {
		switch s.getDistro().Family {
		case config.Raspbian:
			needToSetupCache = true
			break
		case config.Ubuntu, config.Debian:
			//TODO changelopg cache for RedHat, Oracle, Amazon, CentOS is not implemented yet.
			if s.getServerInfo().Mode.IsDeep() {
				needToSetupCache = true
			}
			break
		}
	}
	if needToSetupCache {
		if err := cache.SetupBolt(config.Conf.CacheDBPath, util.Log); err != nil {
			return err
		}
	}
	return nil
}

func scanVulns(jsonDir string, scannedAt time.Time, timeoutSec int) error {
	var results models.ScanResults
	parallelExec(func(o osTypeInterface) (err error) {
		if err = o.preCure(); err != nil {
			return err
		}
		if err = o.scanPackages(); err != nil {
			return err
		}
		if err = o.scanWordPress(); err != nil {
			return xerrors.Errorf("Failed to scan WordPress: %w", err)
		}
		if err = o.scanLibraries(); err != nil {
			return xerrors.Errorf("Failed to scan Library: %w", err)
		}
		return o.postScan()
	}, timeoutSec)

	hostname, _ := os.Hostname()
	ipv4s, ipv6s, err := util.IP()
	if err != nil {
		util.Log.Errorf("Failed to fetch scannedIPs. err: %+v", err)
	}

	for _, s := range append(servers, errServers...) {
		r := s.convertToModel()
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

	config.Conf.FormatJSON = true
	ws := []report.ResultWriter{
		report.LocalFileWriter{CurrentDir: jsonDir},
	}
	for _, w := range ws {
		if err := w.Write(results...); err != nil {
			return xerrors.Errorf("Failed to write summary report: %s", err)
		}
	}

	report.StdoutWriter{}.WriteScanSummary(results...)

	errServerNames := []string{}
	for _, r := range results {
		if 0 < len(r.Errors) {
			errServerNames = append(errServerNames, r.ServerName)
		}
	}
	if 0 < len(errServerNames) {
		return fmt.Errorf("An error occurred on %s", errServerNames)
	}

	return nil
}

// EnsureResultDir ensures the directory for scan results
func EnsureResultDir(scannedAt time.Time) (currentDir string, err error) {
	jsonDirName := scannedAt.Format(time.RFC3339)

	resultsDir := config.Conf.ResultsDir
	if len(resultsDir) == 0 {
		wd, _ := os.Getwd()
		resultsDir = filepath.Join(wd, "results")
	}
	jsonDir := filepath.Join(resultsDir, jsonDirName)
	if err := os.MkdirAll(jsonDir, 0700); err != nil {
		return "", xerrors.Errorf("Failed to create dir: %w", err)
	}

	symlinkPath := filepath.Join(resultsDir, "current")
	if _, err := os.Lstat(symlinkPath); err == nil {
		if err := os.Remove(symlinkPath); err != nil {
			return "", xerrors.Errorf(
				"Failed to remove symlink. path: %s, err: %w", symlinkPath, err)
		}
	}

	if err := os.Symlink(jsonDir, symlinkPath); err != nil {
		return "", xerrors.Errorf(
			"Failed to create symlink: path: %s, err: %w", symlinkPath, err)
	}
	return jsonDir, nil
}
