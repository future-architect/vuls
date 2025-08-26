package scanner

import (
	"fmt"
	"maps"
	"math/rand"
	"net/http"
	"os"
	ex "os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	xos "github.com/aquasecurity/trivy/pkg/x/os"
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

var userDirectoryPath = ""

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
	serverName := header.Get("X-Vuls-Server-Name")
	if toLocalFile && serverName == "" {
		return models.ScanResult{}, errServerNameHeader
	}

	family := header.Get("X-Vuls-OS-Family")
	if family == "" {
		return models.ScanResult{}, errOSFamilyHeader
	}

	switch family {
	case constant.Windows:
		osInfo, hotfixs, err := parseSystemInfo(toUTF8(body))
		if err != nil {
			return models.ScanResult{}, xerrors.Errorf("Failed to parse systeminfo.exe. err: %w", err)
		}

		release := header.Get("X-Vuls-OS-Release")
		if release == "" {
			logging.Log.Debugf("osInfo(systeminfo.exe): %+v", osInfo)
			release, err = detectOSName(osInfo)
			if err != nil {
				return models.ScanResult{}, xerrors.Errorf("Failed to detect os name. err: %w", err)
			}
		}

		kernelVersion := header.Get("X-Vuls-Kernel-Version")
		if kernelVersion == "" {
			kernelVersion = formatKernelVersion(osInfo)
		}

		kbs, err := DetectKBsFromKernelVersion(release, kernelVersion)
		if err != nil {
			return models.ScanResult{}, xerrors.Errorf("Failed to detect KBs from kernel version. err: %w", err)
		}

		applied, unapplied := map[string]struct{}{}, map[string]struct{}{}
		for _, kb := range hotfixs {
			applied[kb] = struct{}{}
		}
		for _, kb := range kbs.Applied {
			applied[kb] = struct{}{}
		}
		for _, kb := range kbs.Unapplied {
			unapplied[kb] = struct{}{}
		}

		return models.ScanResult{
			ServerName: serverName,
			Family:     family,
			Release:    release,
			RunningKernel: models.Kernel{
				Version: kernelVersion,
			},
			WindowsKB:   &models.WindowsKB{Applied: slices.Collect(maps.Keys(applied)), Unapplied: slices.Collect(maps.Keys(unapplied))},
			ScannedCves: models.VulnInfos{},
		}, nil
	default:
		release := header.Get("X-Vuls-OS-Release")
		if release == "" {
			return models.ScanResult{}, errOSReleaseHeader
		}

		kernelRelease := header.Get("X-Vuls-Kernel-Release")
		if kernelRelease == "" {
			logging.Log.Warn("If X-Vuls-Kernel-Release is not specified, there is a possibility of false detection")
		}

		kernelVersion := header.Get("X-Vuls-Kernel-Version")

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
	case constant.Alpine:
		osType = &alpine{base: base}
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
	case constant.OpenSUSE, constant.OpenSUSELeap, constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		osType = &suse{redhatBase: redhatBase{base: base}}
	case constant.Windows:
		osType = &windows{base: base}
	case constant.MacOSX, constant.MacOSXServer, constant.MacOS, constant.MacOSServer:
		osType = &macos{base: base}
	default:
		return models.Packages{}, models.SrcPackages{}, xerrors.Errorf("Server mode for %s is not implemented yet", base.Distro.Family)
	}

	return osType.parseInstalledPackages(pkgList)
}

// initServers detect the kind of OS distribution of target servers
func (s Scanner) initServers() error {
	hosts, errHosts := s.detectServerOSes()
	if (len(hosts) + len(errHosts)) == 0 {
		return xerrors.New("No host defined. Check the configuration")
	}

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

	if (len(servers) + len(errServers)) == 0 {
		return xerrors.New("No server defined. Check the configuration")
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

	if runtime.GOOS == "windows" {
		c.Distro.Family = constant.Windows
	}
	defer func(c *config.ServerInfo) {
		c.Distro.Family = ""
	}(c)

	sshBinaryPath, err := lookpath(c.Distro.Family, "ssh")
	if err != nil {
		return xerrors.Errorf("Failed to lookup ssh binary path. err: %w", err)
	}

	sshConfigCmd := buildSSHConfigCmd(sshBinaryPath, c)
	logging.Log.Debugf("Executing... %s", strings.ReplaceAll(sshConfigCmd, "\n", ""))
	configResult := localExec(*c, sshConfigCmd, noSudo)
	if !configResult.isSuccess() {
		if strings.Contains(configResult.Stderr, "unknown option -- G") {
			logging.Log.Warn("SSH configuration validation is skipped. To enable validation, G option introduced in OpenSSH 6.8 must be enabled.")
			return nil
		}
		return xerrors.Errorf("Failed to print SSH configuration. err: %w", configResult.Error)
	}
	sshConfig := parseSSHConfiguration(configResult.Stdout)
	c.User = sshConfig.user
	logging.Log.Debugf("Setting SSH User:%s for Server:%s ...", sshConfig.user, c.GetServerName())
	c.Port = sshConfig.port
	logging.Log.Debugf("Setting SSH Port:%s for Server:%s ...", sshConfig.port, c.GetServerName())
	if c.User == "" || c.Port == "" {
		return xerrors.New("Failed to find User or Port setting. Please check the User or Port settings for SSH")
	}

	if sshConfig.strictHostKeyChecking == "false" {
		return nil
	}
	if sshConfig.proxyCommand != "" || sshConfig.proxyJump != "" {
		logging.Log.Debug("known_host check under Proxy is not yet implemented")
		return nil
	}

	logging.Log.Debugf("Checking if the host's public key is in known_hosts...")
	knownHostsPaths := []string{}
	for _, knownHost := range append(sshConfig.userKnownHosts, sshConfig.globalKnownHosts...) {
		if knownHost != "" && knownHost != "/dev/null" {
			knownHostsPaths = append(knownHostsPaths, knownHost)
		}
	}
	if len(knownHostsPaths) == 0 {
		return xerrors.New("Failed to find any known_hosts to use. Please check the UserKnownHostsFile and GlobalKnownHostsFile settings for SSH")
	}

	sshKeyscanBinaryPath, err := lookpath(c.Distro.Family, "ssh-keyscan")
	if err != nil {
		return xerrors.Errorf("Failed to lookup ssh-keyscan binary path. err: %w", err)
	}
	sshScanCmd := strings.Join([]string{sshKeyscanBinaryPath, "-p", c.Port, sshConfig.hostname}, " ")
	r := localExec(*c, sshScanCmd, noSudo)
	if !r.isSuccess() {
		logging.Log.Warnf("SSH configuration validation is skipped. err: Failed to ssh-keyscan. cmd: %s, err: %s", sshScanCmd, r.Error)
		return nil
	}
	serverKeys := parseSSHScan(r.Stdout)

	sshKeygenBinaryPath, err := lookpath(c.Distro.Family, "ssh-keygen")
	if err != nil {
		return xerrors.Errorf("Failed to lookup ssh-keygen binary path. err: %w", err)
	}
	for _, knownHosts := range knownHostsPaths {
		var hostname string
		if sshConfig.hostKeyAlias != "" {
			hostname = sshConfig.hostKeyAlias
		} else {
			if c.Port != "" && c.Port != "22" {
				hostname = fmt.Sprintf("\"[%s]:%s\"", sshConfig.hostname, c.Port)
			} else {
				hostname = sshConfig.hostname
			}
		}
		cmd := fmt.Sprintf("%s -F %s -f %s", sshKeygenBinaryPath, hostname, knownHosts)
		logging.Log.Debugf("Executing... %s", strings.ReplaceAll(cmd, "\n", ""))
		if r := localExec(*c, cmd, noSudo); r.isSuccess() {
			keyType, clientKey, err := parseSSHKeygen(r.Stdout)
			if err != nil {
				logging.Log.Warnf("SSH configuration validation is skipped. err: Failed to parse ssh-keygen result. stdout: %s, err: %s", r.Stdout, r.Error)
				return nil
			}
			if serverKey, ok := serverKeys[keyType]; ok && serverKey == clientKey {
				return nil
			}
			return xerrors.Errorf("Failed to find the server key that matches the key registered in the client. The server key may have been changed. Please exec `$ %s` and `$ %s` or `$ %s`",
				fmt.Sprintf("%s -R %s -f %s", sshKeygenBinaryPath, hostname, knownHosts),
				strings.Join(buildSSHBaseCmd(sshBinaryPath, c, nil), " "),
				buildSSHKeyScanCmd(sshKeyscanBinaryPath, c.Port, knownHostsPaths[0], sshConfig))
		}
	}
	return xerrors.Errorf("Failed to find the host in known_hosts. Please exec `$ %s` or `$ %s`",
		strings.Join(buildSSHBaseCmd(sshBinaryPath, c, nil), " "),
		buildSSHKeyScanCmd(sshKeyscanBinaryPath, c.Port, knownHostsPaths[0], sshConfig))
}

func lookpath(family, file string) (string, error) {
	switch family {
	case constant.Windows:
		return fmt.Sprintf("%s.exe", strings.TrimPrefix(file, ".exe")), nil
	default:
		p, err := ex.LookPath(file)
		if err != nil {
			return "", err
		}
		return p, nil
	}
}

func buildSSHBaseCmd(sshBinaryPath string, c *config.ServerInfo, options []string) []string {
	cmd := []string{sshBinaryPath}
	if len(options) > 0 {
		cmd = append(cmd, options...)
	}
	if c.SSHConfigPath != "" {
		cmd = append(cmd, "-F", c.SSHConfigPath)
	}
	if c.KeyPath != "" {
		cmd = append(cmd, "-i", c.KeyPath)
	}
	if c.Port != "" {
		cmd = append(cmd, "-p", c.Port)
	}
	if c.User != "" {
		cmd = append(cmd, "-l", c.User)
	}
	if len(c.JumpServer) > 0 {
		cmd = append(cmd, "-J", strings.Join(c.JumpServer, ","))
	}
	cmd = append(cmd, c.Host)
	return cmd
}

func buildSSHConfigCmd(sshBinaryPath string, c *config.ServerInfo) string {
	return strings.Join(buildSSHBaseCmd(sshBinaryPath, c, []string{"-G"}), " ")
}

func buildSSHKeyScanCmd(sshKeyscanBinaryPath, port, knownHosts string, sshConfig sshConfiguration) string {
	cmd := []string{sshKeyscanBinaryPath}
	if sshConfig.hashKnownHosts == "yes" {
		cmd = append(cmd, "-H")
	}
	if port != "" {
		cmd = append(cmd, "-p", port)
	}
	return strings.Join(append(cmd, sshConfig.hostname, ">>", knownHosts), " ")
}

type sshConfiguration struct {
	hostname              string
	hostKeyAlias          string
	hashKnownHosts        string
	user                  string
	port                  string
	strictHostKeyChecking string
	globalKnownHosts      []string
	userKnownHosts        []string
	proxyCommand          string
	proxyJump             string
}

func parseSSHConfiguration(stdout string) sshConfiguration {
	sshConfig := sshConfiguration{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSuffix(line, "\r")
		switch {
		case strings.HasPrefix(line, "user "):
			sshConfig.user = strings.TrimPrefix(line, "user ")
		case strings.HasPrefix(line, "hostname "):
			sshConfig.hostname = strings.TrimPrefix(line, "hostname ")
		case strings.HasPrefix(line, "hostkeyalias "):
			sshConfig.hostKeyAlias = strings.TrimPrefix(line, "hostkeyalias ")
		case strings.HasPrefix(line, "hashknownhosts "):
			sshConfig.hashKnownHosts = strings.TrimPrefix(line, "hashknownhosts ")
		case strings.HasPrefix(line, "port "):
			sshConfig.port = strings.TrimPrefix(line, "port ")
		case strings.HasPrefix(line, "stricthostkeychecking "):
			sshConfig.strictHostKeyChecking = strings.TrimPrefix(line, "stricthostkeychecking ")
		case strings.HasPrefix(line, "globalknownhostsfile "):
			sshConfig.globalKnownHosts = strings.Split(strings.TrimPrefix(line, "globalknownhostsfile "), " ")
		case strings.HasPrefix(line, "userknownhostsfile "):
			sshConfig.userKnownHosts = strings.Split(strings.TrimPrefix(line, "userknownhostsfile "), " ")
			if runtime.GOOS == constant.Windows {
				for i, userKnownHost := range sshConfig.userKnownHosts {
					if strings.HasPrefix(userKnownHost, "~") {
						sshConfig.userKnownHosts[i] = normalizeHomeDirPathForWindows(userKnownHost)
					}
				}
			}
		case strings.HasPrefix(line, "proxycommand "):
			sshConfig.proxyCommand = strings.TrimPrefix(line, "proxycommand ")
		case strings.HasPrefix(line, "proxyjump "):
			sshConfig.proxyJump = strings.TrimPrefix(line, "proxyjump ")
		}
	}
	return sshConfig
}

func normalizeHomeDirPathForWindows(userKnownHost string) string {
	userKnownHostPath := filepath.Join(os.Getenv("userprofile"), strings.TrimPrefix(userKnownHost, "~"))
	return strings.ReplaceAll(userKnownHostPath, "/", "\\")
}

func parseSSHScan(stdout string) map[string]string {
	keys := map[string]string{}
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}
		if ss := strings.Split(line, " "); len(ss) == 3 {
			keys[ss[1]] = ss[2]
		}
	}
	return keys
}

func parseSSHKeygen(stdout string) (string, string, error) {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "# ") {
			continue
		}

		// HashKnownHosts yes
		if strings.HasPrefix(line, "|1|") {
			ss := strings.Split(line, "|")
			if ss := strings.Split(ss[len(ss)-1], " "); len(ss) == 3 {
				return ss[1], ss[2], nil
			}
		} else {
			if ss := strings.Split(line, " "); len(ss) == 3 {
				return ss[1], ss[2], nil
			}
		}
	}
	return "", "", xerrors.New("Failed to parse ssh-keygen result. err: public key not found")
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

	if !isLocalExec(c.Port, c.Host) {
		if err := testFirstSSHConnection(c); err != nil {
			osType := &unknown{base{ServerInfo: c}}
			osType.setErrs([]error{xerrors.Errorf("Failed to test first SSH Connection. err: %w", err)})
			return osType
		}
	}

	if itsMe, osType := detectWindows(c); itsMe {
		logging.Log.Debugf("Windows. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	if itsMe, osType := detectDebian(c); itsMe {
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

	if itsMe, osType := detectMacOS(c); itsMe {
		logging.Log.Debugf("MacOS. Host: %s:%s", c.Host, c.Port)
		return osType
	}

	osType := &unknown{base{ServerInfo: c}}
	osType.setErrs([]error{xerrors.New("Unknown OS Type")})
	return osType
}

func testFirstSSHConnection(c config.ServerInfo) error {
	for i := 3; i > 0; i-- {
		rChan := make(chan execResult, 1)
		go func() {
			rChan <- exec(c, "exit", noSudo)
		}()
		select {
		case r := <-rChan:
			if r.ExitStatus == 255 {
				return xerrors.Errorf("Unable to connect via SSH. Scan with -vvv option to print SSH debugging messages and check SSH settings.\n%s", r)
			}
			return nil
		case <-time.After(time.Duration(3) * time.Second):
		}
	}
	logging.Log.Warnf("First SSH Connection to Host: %s:%s timeout", c.Host, c.Port)
	return nil
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
}

// checkIfSudoNoPasswd checks whether vuls can sudo with nopassword via SSH
func (s Scanner) checkIfSudoNoPasswd() {
	parallelExec(func(o osTypeInterface) error {
		return o.checkIfSudoNoPasswd()
	}, s.TimeoutSec)
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
	if (len(servers) + len(errServers)) == 0 {
		return xerrors.New("No server defined. Check the configuration")
	}

	if err := s.setupChangelogCache(); err != nil {
		return err
	}
	if cache.DB != nil {
		defer cache.DB.Close()
	}

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
	if func() bool {
		for _, s := range servers {
			switch s.getDistro().Family {
			case constant.Raspbian:
				return true
			case constant.Ubuntu, constant.Debian:
				//TODO changelog cache for RedHat, Oracle, Amazon, CentOS is not implemented yet.
				if s.getServerInfo().Mode.IsDeep() {
					return true
				}
			}
		}
		return false
	}() {
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
	if slices.ContainsFunc([][]osTypeInterface{servers, errServers}, func(ss []osTypeInterface) bool {
		return slices.ContainsFunc(ss, func(s osTypeInterface) bool { return s.getServerInfo().Module.IsScanLockFile() })
	}) {
		if err := xos.Cleanup(); err != nil {
			logging.Log.Warnf("Failed to cleanup /tmp/trivy-* directory: %+v", err)
		}
	}

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
