/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
)

// Log for localhsot
var Log *logrus.Entry

var servers []osTypeInterface

// Base Interface of redhat, debian, freebsd
type osTypeInterface interface {
	setServerInfo(config.ServerInfo)
	getServerInfo() config.ServerInfo

	setDistro(string, string)
	getDistro() config.Distro

	// checkDependencies checks if dependencies are installed on the target server.
	checkDependencies() error
	getLackDependencies() []string

	checkIfSudoNoPasswd() error
	detectPlatform() error
	getPlatform() models.Platform

	checkRequiredPackagesInstalled() error
	scanPackages() error
	install() error
	convertToModel() (models.ScanResult, error)

	runningContainers() ([]config.Container, error)
	exitedContainers() ([]config.Container, error)
	allContainers() ([]config.Container, error)

	getErrs() []error
	setErrs([]error)
}

// osPackages is included by base struct
type osPackages struct {
	// installed packages
	Packages models.PackageInfoList

	// unsecure packages
	VulnInfos models.VulnInfos
}

func (p *osPackages) setPackages(pi models.PackageInfoList) {
	p.Packages = pi
}

func (p *osPackages) setVulnInfos(vi []models.VulnInfo) {
	p.VulnInfos = vi
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
func InitServers(localLogger *logrus.Entry) error {
	Log = localLogger
	servers = detectServerOSes()
	if len(servers) == 0 {
		return fmt.Errorf("No scannable servers")
	}

	containers := detectContainerOSes()
	if config.Conf.ContainersOnly {
		servers = containers
	} else {
		servers = append(servers, containers...)
	}
	return nil
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
					res.getDistro())
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
						p, s.getServerInfo().GetServerName())
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
					sinfo.Container.Name, sinfo.ServerName, osi.getDistro())
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
	timeoutSec := 15
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
	errs := parallelSSHExec(func(o osTypeInterface) error {
		if err := o.checkDependencies(); err != nil {
			return err
		}
		return nil
	})
	if len(errs) != 0 {
		return errs
	}

	var targets []osTypeInterface
	for _, s := range servers {
		deps := s.getLackDependencies()
		if len(deps) != 0 {
			targets = append(targets, s)
		}
	}
	if len(targets) == 0 {
		Log.Info("No need to install dependencies")
		return nil
	}

	Log.Info("The following servers need dependencies installed")
	for _, s := range targets {
		for _, d := range s.getLackDependencies() {
			Log.Infof("  - %s on %s", d, s.getServerInfo().GetServerName())
		}
	}

	if !config.Conf.AssumeYes {
		Log.Info("Is this ok to install dependencies on the servers? [y/N]")

		reader := bufio.NewReader(os.Stdin)
		for {
			text, err := reader.ReadString('\n')
			if err != nil {
				return []error{err}
			}
			switch strings.TrimSpace(text) {
			case "", "N", "n":
				return nil
			case "y", "Y":
				goto yes
			default:
				Log.Info("Please enter y or N")
			}
		}
	}

yes:
	servers = targets
	errs = parallelSSHExec(func(o osTypeInterface) error {
		if err := o.install(); err != nil {
			return err
		}
		return nil
	})
	if len(errs) != 0 {
		return errs
	}
	Log.Info("All dependencies were installed correctly")
	return nil
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

	if err := setupCangelogCache(); err != nil {
		return []error{err}
	}

	defer func() {
		if cache.DB != nil {
			cache.DB.Close()
		}
	}()

	Log.Info("Scanning vulnerable OS packages...")
	scannedAt := time.Now()
	dir, err := ensureResultDir(scannedAt)
	if err != nil {
		return []error{err}
	}
	if errs := scanVulns(dir, scannedAt); errs != nil {
		return errs
	}

	return nil
}

func setupCangelogCache() error {
	needToSetupCache := false
	for _, s := range servers {
		switch s.getDistro().Family {
		case "ubuntu", "debian":
			needToSetupCache = true
			break
		}
	}
	if needToSetupCache {
		if err := cache.SetupBolt(config.Conf.CacheDBPath, Log); err != nil {
			return err
		}
	}
	return nil
}

func checkRequiredPackagesInstalled() []error {
	timeoutSec := 30 * 60
	return parallelSSHExec(func(o osTypeInterface) error {
		return o.checkRequiredPackagesInstalled()
	}, timeoutSec)
}

func scanVulns(jsonDir string, scannedAt time.Time) []error {
	var results models.ScanResults
	timeoutSec := 120 * 60
	errs := parallelSSHExec(func(o osTypeInterface) error {
		if err := o.scanPackages(); err != nil {
			return err
		}

		r, err := o.convertToModel()
		if err != nil {
			return err
		}
		r.ScannedAt = scannedAt
		results = append(results, r)

		return nil
	}, timeoutSec)

	config.Conf.FormatJSON = true
	ws := []report.ResultWriter{
		report.LocalFileWriter{CurrentDir: jsonDir},
	}
	for _, w := range ws {
		if err := w.Write(results...); err != nil {
			return []error{
				fmt.Errorf("Failed to write summary report: %s", err),
			}
		}
	}
	if errs != nil {
		return errs
	}

	report.StdoutWriter{}.WriteScanSummary(results...)
	return nil
}

func ensureResultDir(scannedAt time.Time) (currentDir string, err error) {
	jsonDirName := scannedAt.Format(time.RFC3339)

	resultsDir := config.Conf.ResultsDir
	if len(resultsDir) == 0 {
		wd, _ := os.Getwd()
		resultsDir = filepath.Join(wd, "results")
	}
	jsonDir := filepath.Join(resultsDir, jsonDirName)
	if err := os.MkdirAll(jsonDir, 0700); err != nil {
		return "", fmt.Errorf("Failed to create dir: %s", err)
	}

	symlinkPath := filepath.Join(resultsDir, "current")
	if _, err := os.Lstat(symlinkPath); err == nil {
		if err := os.Remove(symlinkPath); err != nil {
			return "", fmt.Errorf(
				"Failed to remove symlink. path: %s, err: %s", symlinkPath, err)
		}
	}

	if err := os.Symlink(jsonDir, symlinkPath); err != nil {
		return "", fmt.Errorf(
			"Failed to create symlink: path: %s, err: %s", symlinkPath, err)
	}
	return jsonDir, nil
}
