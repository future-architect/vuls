package scanner

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"
	ex "os/exec"
	"strings"
	"time"

	debver "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

const (
	scannedViaRemote = "remote"
	scannedViaLocal  = "local"
	scannedViaPseudo = "pseudo"
)

var (
	errOSFamilyHeader   = xerrors.New("X-Vuls-OS-Family header is required")
	errOSReleaseHeader  = xerrors.New("X-Vuls-OS-Release header is required")
	errServerNameHeader = xerrors.New("X-Vuls-Server-Name header is required")
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
	if family == constant.Debian {
		if kernelVersion == "" {
			logging.Log.Warn("X-Vuls-Kernel-Version is empty. skip kernel vulnerability detection.")
		} else {
			if _, err := debver.NewVersion(kernelVersion); err != nil {
				logging.Log.Warnf("X-Vuls-Kernel-Version is invalid. skip kernel vulnerability detection. actual kernelVersion: %s, err: %s", kernelVersion, err)
				kernelVersion = ""
			}
		}
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
	case constant.Alma:
		osType = &alma{redhatBase: redhatBase{base: base}}
	case constant.Rocky:
		osType = &rocky{redhatBase: redhatBase{base: base}}
	case constant.Oracle:
		osType = &oracle{redhatBase: redhatBase{base: base}}
	case constant.Amazon:
		osType = &amazon{redhatBase: redhatBase{base: base}}
	case constant.Fedora:
		osType = &fedora{redhatBase: redhatBase{base: base}}
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
			if err := validateSSHConfig(&srv); err != nil {
				checkOS := unknown{base{ServerInfo: srv}}
				checkOS.setErrs([]error{err})
				osTypeChan <- &checkOS
				return
			}
			osTypeChan <- s.detectOS(srv)
		}(target)
	}

	timeout := time.After(time.Duration(s.TimeoutSec) * time.Second)
	for i := 0; i < len(s.Targets); i++ {
		select {
		case res := <-osTypeChan:
			if 0 < len(res.getErrs()) {
				errServers = append(errServers, res)
				logging.Log.Errorf("(%d/%d) Failed: %s, err: %+v", i+1, len(s.Targets), res.getServerInfo().ServerName, res.getErrs())
			} else {
				servers = append(servers, res)
				logging.Log.Infof("(%d/%d) Detected: %s: %s", i+1, len(s.Targets), res.getServerInfo().ServerName, res.getDistro())
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

func validateSSHConfig(c *config.ServerInfo) error {
	if isLocalExec(c.Port, c.Host) || c.Type == constant.ServerTypePseudo {
		return nil
	}

	logging.Log.Debugf("Validating SSH Settings for Server:%s ...", c.GetServerName())

	sshBinaryPath, err := ex.LookPath("ssh")
	if err != nil {
		return xerrors.Errorf("Failed to lookup ssh binary path. err: %w", err)
	}
	sshKeygenBinaryPath, err := ex.LookPath("ssh-keygen")
	if err != nil {
		return xerrors.Errorf("Failed to lookup ssh-keygen binary path. err: %w", err)
	}

	sshConfigCmd := []string{sshBinaryPath, "-G"}
	if c.SSHConfigPath != "" {
		sshConfigCmd = append(sshConfigCmd, "-F", c.SSHConfigPath)
	}
	if c.Port != "" {
		sshConfigCmd = append(sshConfigCmd, "-p", c.Port)
	}
	if c.User != "" {
		sshConfigCmd = append(sshConfigCmd, "-l", c.User)
	}
	if len(c.JumpServer) > 0 {
		sshConfigCmd = append(sshConfigCmd, "-J", strings.Join(c.JumpServer, ","))
	}
	sshConfigCmd = append(sshConfigCmd, c.Host)
	cmd := strings.Join(sshConfigCmd, " ")
	logging.Log.Debugf("Executing... %s", strings.Replace(cmd, "\n", "", -1))
	r := localExec(*c, cmd, noSudo)
	if !r.isSuccess() {
		return xerrors.Errorf("Failed to print SSH configuration. err: %w", r.Error)
	}

	var (
		hostname              string
		strictHostKeyChecking string
		globalKnownHosts      string
		userKnownHosts        string
		proxyCommand          string
		proxyJump             string
	)
	for _, line := range strings.Split(r.Stdout, "\n") {
		switch {
		case strings.HasPrefix(line, "user "):
			user := strings.TrimPrefix(line, "user ")
			logging.Log.Debugf("Setting SSH User:%s for Server:%s ...", user, c.GetServerName())
			c.User = user
		case strings.HasPrefix(line, "hostname "):
			hostname = strings.TrimPrefix(line, "hostname ")
		case strings.HasPrefix(line, "port "):
			port := strings.TrimPrefix(line, "port ")
			logging.Log.Debugf("Setting SSH Port:%s for Server:%s ...", port, c.GetServerName())
			c.Port = port
		case strings.HasPrefix(line, "stricthostkeychecking "):
			strictHostKeyChecking = strings.TrimPrefix(line, "stricthostkeychecking ")
		case strings.HasPrefix(line, "globalknownhostsfile "):
			globalKnownHosts = strings.TrimPrefix(line, "globalknownhostsfile ")
		case strings.HasPrefix(line, "userknownhostsfile "):
			userKnownHosts = strings.TrimPrefix(line, "userknownhostsfile ")
		case strings.HasPrefix(line, "proxycommand "):
			proxyCommand = strings.TrimPrefix(line, "proxycommand ")
		case strings.HasPrefix(line, "proxyjump "):
			proxyJump = strings.TrimPrefix(line, "proxyjump ")
		}
	}
	if c.User == "" || c.Port == "" {
		return xerrors.New("Failed to find User or Port setting. Please check the User or Port settings for SSH")
	}
	if strictHostKeyChecking == "false" || proxyCommand != "" || proxyJump != "" {
		return nil
	}

	logging.Log.Debugf("Checking if the host's public key is in known_hosts...")
	knownHostsPaths := []string{}
	for _, knownHosts := range []string{userKnownHosts, globalKnownHosts} {
		for _, knownHost := range strings.Split(knownHosts, " ") {
			if knownHost != "" && knownHost != "/dev/null" {
				knownHostsPaths = append(knownHostsPaths, knownHost)
			}
		}
	}
	if len(knownHostsPaths) == 0 {
		return xerrors.New("Failed to find any known_hosts to use. Please check the UserKnownHostsFile and GlobalKnownHostsFile settings for SSH")
	}

	for _, knownHosts := range knownHostsPaths {
		if c.Port != "" && c.Port != "22" {
			cmd := fmt.Sprintf("%s -F %s -f %s", sshKeygenBinaryPath, fmt.Sprintf("\"[%s]:%s\"", hostname, c.Port), knownHosts)
			logging.Log.Debugf("Executing... %s", strings.Replace(cmd, "\n", "", -1))
			if r := localExec(*c, cmd, noSudo); r.isSuccess() {
				return nil
			}
		}
		cmd := fmt.Sprintf("%s -F %s -f %s", sshKeygenBinaryPath, hostname, knownHosts)
		logging.Log.Debugf("Executing... %s", strings.Replace(cmd, "\n", "", -1))
		if r := localExec(*c, cmd, noSudo); r.isSuccess() {
			return nil
		}
	}

	sshConnArgs := []string{}
	sshKeyScanArgs := []string{"-H"}
	if c.SSHConfigPath != "" {
		sshConnArgs = append(sshConnArgs, "-F", c.SSHConfigPath)
	}
	if c.KeyPath != "" {
		sshConnArgs = append(sshConnArgs, "-i", c.KeyPath)
	}
	if c.Port != "" {
		sshConnArgs = append(sshConnArgs, "-p", c.Port)
		sshKeyScanArgs = append(sshKeyScanArgs, "-p", c.Port)
	}
	if c.User != "" {
		sshConnArgs = append(sshConnArgs, "-l", c.User)
	}
	sshConnArgs = append(sshConnArgs, c.Host)
	sshKeyScanArgs = append(sshKeyScanArgs, fmt.Sprintf("%s >> %s", hostname, knownHostsPaths[0]))
	sshConnCmd := fmt.Sprintf("ssh %s", strings.Join(sshConnArgs, " "))
	sshKeyScancmd := fmt.Sprintf("ssh-keyscan %s", strings.Join(sshKeyScanArgs, " "))
	return xerrors.Errorf("Failed to find the host in known_hosts. Please exec `$ %s` or `$ %s`", sshConnCmd, sshKeyScancmd)
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

func (s Scanner) detectOS(c config.ServerInfo) osTypeInterface {
	if itsMe, osType, _ := detectPseudo(c); itsMe {
		return osType
	}

	if itsMe, osType, fatalErr := s.detectDebianWithRetry(c); fatalErr != nil {
		osType.setErrs([]error{xerrors.Errorf("Failed to detect OS: %w", fatalErr)})
		return osType
	} else if itsMe {
		logging.Log.Debugf("Debian based Linux. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	if itsMe, osType := detectRedhat(c); itsMe {
		logging.Log.Debugf("Redhat based Linux. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	if itsMe, osType := detectSUSE(c); itsMe {
		logging.Log.Debugf("SUSE Linux. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	if itsMe, osType := detectFreebsd(c); itsMe {
		logging.Log.Debugf("FreeBSD. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	if itsMe, osType := detectAlpine(c); itsMe {
		logging.Log.Debugf("Alpine. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	osType := &unknown{base{ServerInfo: c}}
	osType.setErrs([]error{xerrors.New("Unknown OS Type")})
	return osType
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
				// continue scanning
				logging.Log.Warnf("Failed to scan Ports: %+v", err)
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
