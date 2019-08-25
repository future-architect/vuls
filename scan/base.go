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
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"

	// Import library scanner
	_ "github.com/aquasecurity/fanal/analyzer/library/bundler"
	_ "github.com/aquasecurity/fanal/analyzer/library/cargo"
	_ "github.com/aquasecurity/fanal/analyzer/library/composer"
	_ "github.com/aquasecurity/fanal/analyzer/library/npm"
	_ "github.com/aquasecurity/fanal/analyzer/library/pipenv"
	_ "github.com/aquasecurity/fanal/analyzer/library/poetry"
	_ "github.com/aquasecurity/fanal/analyzer/library/yarn"
)

type base struct {
	ServerInfo config.ServerInfo
	Distro     config.Distro
	Platform   models.Platform
	osPackages
	LibraryScanners []models.LibraryScanner
	WordPress       *models.WordPressPackages

	log   *logrus.Entry
	errs  []error
	warns []error
}

func (l *base) exec(cmd string, sudo bool) execResult {
	return exec(l.ServerInfo, cmd, sudo, l.log)
}

func (l *base) setServerInfo(c config.ServerInfo) {
	l.ServerInfo = c
}

func (l *base) getServerInfo() config.ServerInfo {
	return l.ServerInfo
}

func (l *base) setDistro(fam, rel string) {
	d := config.Distro{
		Family:  fam,
		Release: rel,
	}
	l.Distro = d

	s := l.getServerInfo()
	s.Distro = d
	l.setServerInfo(s)
}

func (l *base) getDistro() config.Distro {
	return l.Distro
}

func (l *base) setPlatform(p models.Platform) {
	l.Platform = p
}

func (l *base) getPlatform() models.Platform {
	return l.Platform
}

func (l *base) runningKernel() (release, version string, err error) {
	r := l.exec("uname -r", noSudo)
	if !r.isSuccess() {
		return "", "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	release = strings.TrimSpace(r.Stdout)

	switch l.Distro.Family {
	case config.Debian:
		r := l.exec("uname -a", noSudo)
		if !r.isSuccess() {
			return "", "", xerrors.Errorf("Failed to SSH: %s", r)
		}
		ss := strings.Fields(r.Stdout)
		if 6 < len(ss) {
			version = ss[6]
		}
	}
	return
}

func (l *base) allContainers() (containers []config.Container, err error) {
	switch l.ServerInfo.ContainerType {
	case "", "docker":
		stdout, err := l.dockerPs("-a --format '{{.ID}} {{.Names}} {{.Image}}'")
		if err != nil {
			return containers, err
		}
		return l.parseDockerPs(stdout)
	case "lxd":
		stdout, err := l.lxdPs("-c n")
		if err != nil {
			return containers, err
		}
		return l.parseLxdPs(stdout)
	case "lxc":
		stdout, err := l.lxcPs("-1")
		if err != nil {
			return containers, err
		}
		return l.parseLxcPs(stdout)
	default:
		return containers, xerrors.Errorf(
			"Not supported yet: %s", l.ServerInfo.ContainerType)
	}
}

func (l *base) runningContainers() (containers []config.Container, err error) {
	switch l.ServerInfo.ContainerType {
	case "", "docker":
		stdout, err := l.dockerPs("--format '{{.ID}} {{.Names}} {{.Image}}'")
		if err != nil {
			return containers, err
		}
		return l.parseDockerPs(stdout)
	case "lxd":
		stdout, err := l.lxdPs("volatile.last_state.power=RUNNING -c n")
		if err != nil {
			return containers, err
		}
		return l.parseLxdPs(stdout)
	case "lxc":
		stdout, err := l.lxcPs("-1 --running")
		if err != nil {
			return containers, err
		}
		return l.parseLxcPs(stdout)
	default:
		return containers, xerrors.Errorf(
			"Not supported yet: %s", l.ServerInfo.ContainerType)
	}
}

func (l *base) exitedContainers() (containers []config.Container, err error) {
	switch l.ServerInfo.ContainerType {
	case "", "docker":
		stdout, err := l.dockerPs("--filter 'status=exited' --format '{{.ID}} {{.Names}} {{.Image}}'")
		if err != nil {
			return containers, err
		}
		return l.parseDockerPs(stdout)
	case "lxd":
		stdout, err := l.lxdPs("volatile.last_state.power=STOPPED -c n")
		if err != nil {
			return containers, err
		}
		return l.parseLxdPs(stdout)
	case "lxc":
		stdout, err := l.lxcPs("-1 --stopped")
		if err != nil {
			return containers, err
		}
		return l.parseLxcPs(stdout)
	default:
		return containers, xerrors.Errorf(
			"Not supported yet: %s", l.ServerInfo.ContainerType)
	}
}

func (l *base) dockerPs(option string) (string, error) {
	cmd := fmt.Sprintf("docker ps %s", option)
	r := l.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) lxdPs(option string) (string, error) {
	cmd := fmt.Sprintf("lxc list %s", option)
	r := l.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) lxcPs(option string) (string, error) {
	cmd := fmt.Sprintf("lxc-ls %s 2>/dev/null", option)
	r := l.exec(cmd, sudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parseDockerPs(stdout string) (containers []config.Container, err error) {
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			break
		}
		if len(fields) != 3 {
			return containers, xerrors.Errorf("Unknown format: %s", line)
		}
		containers = append(containers, config.Container{
			ContainerID: fields[0],
			Name:        fields[1],
			Image:       fields[2],
		})
	}
	return
}

func (l *base) parseLxdPs(stdout string) (containers []config.Container, err error) {
	lines := strings.Split(stdout, "\n")
	for i, line := range lines[3:] {
		if i%2 == 1 {
			continue
		}
		fields := strings.Fields(strings.Replace(line, "|", " ", -1))
		if len(fields) == 0 {
			break
		}
		if len(fields) != 1 {
			return containers, xerrors.Errorf("Unknown format: %s", line)
		}
		containers = append(containers, config.Container{
			ContainerID: fields[0],
			Name:        fields[0],
		})
	}
	return
}

func (l *base) parseLxcPs(stdout string) (containers []config.Container, err error) {
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			break
		}
		containers = append(containers, config.Container{
			ContainerID: fields[0],
			Name:        fields[0],
		})
	}
	return
}

// ip executes ip command and returns IP addresses
func (l *base) ip() ([]string, []string, error) {
	// e.g.
	// 2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\    link/ether 52:54:00:2a:86:4c brd ff:ff:ff:ff:ff:ff
	// 2: eth0    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
	// 2: eth0    inet6 fe80::5054:ff:fe2a:864c/64 scope link \       valid_lft forever preferred_lft forever
	r := l.exec("/sbin/ip -o addr", noSudo)
	if !r.isSuccess() {
		return nil, nil, xerrors.Errorf("Failed to detect IP address: %v", r)
	}
	ipv4Addrs, ipv6Addrs := l.parseIP(r.Stdout)
	return ipv4Addrs, ipv6Addrs, nil
}

// parseIP parses the results of ip command
func (l *base) parseIP(stdout string) (ipv4Addrs []string, ipv6Addrs []string) {
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ip, _, err := net.ParseCIDR(fields[3])
		if err != nil {
			continue
		}
		if !ip.IsGlobalUnicast() {
			continue
		}
		if ipv4 := ip.To4(); ipv4 != nil {
			ipv4Addrs = append(ipv4Addrs, ipv4.String())
		} else {
			ipv6Addrs = append(ipv6Addrs, ip.String())
		}
	}
	return
}

func (l *base) detectPlatform() {
	if l.getServerInfo().Mode.IsOffline() {
		l.setPlatform(models.Platform{Name: "unknown"})
		return
	}
	ok, instanceID, err := l.detectRunningOnAws()
	if err != nil {
		l.setPlatform(models.Platform{Name: "other"})
		return
	}
	if ok {
		l.setPlatform(models.Platform{
			Name:       "aws",
			InstanceID: instanceID,
		})
		return
	}

	//TODO Azure, GCP...
	l.setPlatform(models.Platform{Name: "other"})
	return
}

var dsFingerPrintPrefix = "AgentStatus.agentCertHash: "

func (l *base) detectDeepSecurity() (fingerprint string, err error) {
	// only work root user
	if l.getServerInfo().Mode.IsFastRoot() {
		if r := l.exec("test -f /opt/ds_agent/dsa_query", sudo); r.isSuccess() {
			cmd := fmt.Sprintf(`/opt/ds_agent/dsa_query -c "GetAgentStatus" | grep %q`, dsFingerPrintPrefix)
			r := l.exec(cmd, sudo)
			if r.isSuccess() {
				line := strings.TrimSpace(r.Stdout)
				return line[len(dsFingerPrintPrefix):], nil
			}
			l.warns = append(l.warns, xerrors.New("Fail to retrieve deepsecurity fingerprint"))
		}
	}
	return "", xerrors.Errorf("Failed to detect deepsecurity %s", l.ServerInfo.ServerName)
}

func (l *base) detectIPSs() {
	if !config.Conf.DetectIPS {
		return
	}

	ips := map[config.IPS]string{}

	fingerprint, err := l.detectDeepSecurity()
	if err != nil {
		return
	}
	ips[config.DeepSecurity] = fingerprint
	l.ServerInfo.IPSIdentifiers = ips
}

func (l *base) detectRunningOnAws() (ok bool, instanceID string, err error) {
	if r := l.exec("type curl", noSudo); r.isSuccess() {
		cmd := "curl --max-time 1 --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/instance-id"
		r := l.exec(cmd, noSudo)
		if r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)
			if !l.isAwsInstanceID(id) {
				return false, "", nil
			}
			return true, id, nil
		}

		switch r.ExitStatus {
		case 28, 7:
			// Not running on AWS
			//  7   Failed to connect to host.
			// 28  operation timeout.
			return false, "", nil
		}
	}

	if r := l.exec("type wget", noSudo); r.isSuccess() {
		cmd := "wget --tries=3 --timeout=1 --no-proxy -q -O - http://169.254.169.254/latest/meta-data/instance-id"
		r := l.exec(cmd, noSudo)
		if r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)
			if !l.isAwsInstanceID(id) {
				return false, "", nil
			}
			return true, id, nil
		}

		switch r.ExitStatus {
		case 4, 8:
			// Not running on AWS
			// 4   Network failure
			// 8   Server issued an error response.
			return false, "", nil
		}
	}
	return false, "", xerrors.Errorf(
		"Failed to curl or wget to AWS instance metadata on %s. container: %s",
		l.ServerInfo.ServerName, l.ServerInfo.Container.Name)
}

// http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/resource-ids.html
var awsInstanceIDPattern = regexp.MustCompile(`^i-[0-9a-f]+$`)

func (l *base) isAwsInstanceID(str string) bool {
	return awsInstanceIDPattern.MatchString(str)
}

func (l *base) convertToModel() models.ScanResult {
	ctype := l.ServerInfo.ContainerType
	if l.ServerInfo.Container.ContainerID != "" && ctype == "" {
		ctype = "docker"
	}
	container := models.Container{
		ContainerID: l.ServerInfo.Container.ContainerID,
		Name:        l.ServerInfo.Container.Name,
		Image:       l.ServerInfo.Container.Image,
		Type:        ctype,
	}

	image := models.Image{
		Name: l.ServerInfo.Image.Name,
		Tag:  l.ServerInfo.Image.Tag,
	}

	errs, warns := []string{}, []string{}
	for _, e := range l.errs {
		errs = append(errs, fmt.Sprintf("%+v", e))
	}
	for _, w := range l.warns {
		warns = append(warns, fmt.Sprintf("%+v", w))
	}

	scannedVia := scannedViaRemote
	if isLocalExec(l.ServerInfo.Port, l.ServerInfo.Host) {
		scannedVia = scannedViaLocal
	} else if l.ServerInfo.Type == config.ServerTypePseudo {
		scannedVia = scannedViaPseudo
	}

	return models.ScanResult{
		JSONVersion:       models.JSONVersion,
		ServerName:        l.ServerInfo.ServerName,
		ScannedAt:         time.Now(),
		ScanMode:          l.ServerInfo.Mode.String(),
		Family:            l.Distro.Family,
		Release:           l.Distro.Release,
		Container:         container,
		Image:             image,
		Platform:          l.Platform,
		IPv4Addrs:         l.ServerInfo.IPv4Addrs,
		IPv6Addrs:         l.ServerInfo.IPv6Addrs,
		IPSIdentifiers:    l.ServerInfo.IPSIdentifiers,
		ScannedCves:       l.VulnInfos,
		ScannedVia:        scannedVia,
		RunningKernel:     l.Kernel,
		Packages:          l.Packages,
		SrcPackages:       l.SrcPackages,
		WordPressPackages: l.WordPress,
		LibraryScanners:   l.LibraryScanners,
		Optional:          l.ServerInfo.Optional,
		Errors:            errs,
		Warnings:          warns,
	}
}

func (l *base) setErrs(errs []error) {
	l.errs = errs
}

func (l *base) getErrs() []error {
	return l.errs
}

const (
	systemd  = "systemd"
	upstart  = "upstart"
	sysVinit = "init"
)

// https://unix.stackexchange.com/questions/196166/how-to-find-out-if-a-system-uses-sysv-upstart-or-systemd-initsystem
func (l *base) detectInitSystem() (string, error) {
	var f func(string) (string, error)
	f = func(cmd string) (string, error) {
		r := l.exec(cmd, sudo)
		if !r.isSuccess() {
			return "", xerrors.Errorf("Failed to stat %s: %s", cmd, r)
		}
		scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
		scanner.Scan()
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "systemd") {
			return systemd, nil
		} else if strings.Contains(line, "upstart") {
			return upstart, nil
		} else if strings.Contains(line, "File: ‘/proc/1/exe’ -> ‘/sbin/init’") ||
			strings.Contains(line, "File: `/proc/1/exe' -> `/sbin/init'") {
			return f("stat /sbin/init")
		} else if line == "File: ‘/sbin/init’" ||
			line == "File: `/sbin/init'" {
			r := l.exec("/sbin/init --version", noSudo)
			if r.isSuccess() {
				if strings.Contains(r.Stdout, "upstart") {
					return upstart, nil
				}
			}
			return sysVinit, nil
		}
		return "", xerrors.Errorf("Failed to detect a init system: %s", line)
	}
	return f("stat /proc/1/exe")
}

func (l *base) detectServiceName(pid string) (string, error) {
	cmd := fmt.Sprintf("systemctl status --quiet --no-pager %s", pid)
	r := l.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to stat %s: %s", cmd, r)
	}
	return l.parseSystemctlStatus(r.Stdout), nil
}

func (l *base) parseSystemctlStatus(stdout string) string {
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	scanner.Scan()
	line := scanner.Text()
	ss := strings.Fields(line)
	if len(ss) < 2 || strings.HasPrefix(line, "Failed to get unit for PID") {
		return ""
	}
	return ss[1]
}

func (l *base) scanLibraries() (err error) {
	// image already detected libraries
	if len(l.LibraryScanners) != 0 {
		return nil
	}

	// library scan for servers need lockfiles
	if len(l.ServerInfo.Lockfiles) == 0 && !l.ServerInfo.FindLock {
		return nil
	}

	libFilemap := extractor.FileMap{}

	detectFiles := l.ServerInfo.Lockfiles

	// auto detect lockfile
	if l.ServerInfo.FindLock {
		findopt := ""
		for filename := range models.LibraryMap {
			findopt += fmt.Sprintf("-name %q -o ", "*"+filename)
		}

		// delete last "-o "
		// find / -name "*package-lock.json" -o -name "*yarn.lock" ... 2>&1 | grep -v "Permission denied"
		cmd := fmt.Sprintf(`find / ` + findopt[:len(findopt)-3] + ` 2>&1 | grep -v "Permission denied"`)
		r := exec(l.ServerInfo, cmd, noSudo)
		if !r.isSuccess() {
			return xerrors.Errorf("Failed to find lock files")
		}
		detectFiles = append(detectFiles, strings.Split(r.Stdout, "\n")...)
	}

	for _, path := range detectFiles {
		if path == "" {
			continue
		}
		// skip already exist
		if _, ok := libFilemap[path]; ok {
			continue
		}
		cmd := fmt.Sprintf("cat %s", path)
		r := exec(l.ServerInfo, cmd, noSudo)
		if !r.isSuccess() {
			return xerrors.Errorf("Failed to get target file: %s, filepath: %s", r, path)
		}
		libFilemap[path] = []byte(r.Stdout)
	}

	results, err := analyzer.GetLibraries(libFilemap)
	if err != nil {
		return xerrors.Errorf("Failed to get libs: %w", err)
	}
	l.LibraryScanners, err = convertLibWithScanner(results)
	if err != nil {
		return xerrors.Errorf("Failed to scan libraries: %w", err)
	}
	return nil
}

func (l *base) scanWordPress() (err error) {
	wpOpts := []string{l.ServerInfo.WordPress.OSUser,
		l.ServerInfo.WordPress.DocRoot,
		l.ServerInfo.WordPress.CmdPath,
		l.ServerInfo.WordPress.WPVulnDBToken,
	}
	var isScanWp, hasEmptyOpt bool
	for _, opt := range wpOpts {
		if opt != "" {
			isScanWp = true
			break
		} else {
			hasEmptyOpt = true
		}
	}
	if !isScanWp {
		return nil
	}

	if hasEmptyOpt {
		return xerrors.Errorf("%s has empty WordPress opts: %s",
			l.getServerInfo().GetServerName(), wpOpts)
	}

	cmd := fmt.Sprintf("sudo -u %s -i -- %s cli version --allow-root",
		l.ServerInfo.WordPress.OSUser,
		l.ServerInfo.WordPress.CmdPath)
	if r := exec(l.ServerInfo, cmd, noSudo); !r.isSuccess() {
		l.ServerInfo.WordPress.WPVulnDBToken = "secret"
		return xerrors.Errorf("Failed to exec `%s`. Check the OS user, command path of wp-cli, DocRoot and permission: %#v", cmd, l.ServerInfo.WordPress)
	}

	wp, err := l.detectWordPress()
	if err != nil {
		return xerrors.Errorf("Failed to scan wordpress: %w", err)
	}
	l.WordPress = wp
	return nil
}

func (l *base) detectWordPress() (*models.WordPressPackages, error) {
	ver, err := l.detectWpCore()
	if err != nil {
		return nil, err
	}

	themes, err := l.detectWpThemes()
	if err != nil {
		return nil, err
	}

	plugins, err := l.detectWpPlugins()
	if err != nil {
		return nil, err
	}

	pkgs := models.WordPressPackages{
		models.WpPackage{
			Name:    models.WPCore,
			Version: ver,
			Type:    models.WPCore,
		},
	}
	pkgs = append(pkgs, themes...)
	pkgs = append(pkgs, plugins...)
	return &pkgs, nil
}

func (l *base) detectWpCore() (string, error) {
	cmd := fmt.Sprintf("sudo -u %s -i -- %s core version --path=%s --allow-root",
		l.ServerInfo.WordPress.OSUser,
		l.ServerInfo.WordPress.CmdPath,
		l.ServerInfo.WordPress.DocRoot)

	r := exec(l.ServerInfo, cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to get wp core version: %s", r)
	}
	return strings.TrimSpace(r.Stdout), nil
}

func (l *base) detectWpThemes() ([]models.WpPackage, error) {
	cmd := fmt.Sprintf("sudo -u %s -i -- %s theme list --path=%s --format=json --allow-root",
		l.ServerInfo.WordPress.OSUser,
		l.ServerInfo.WordPress.CmdPath,
		l.ServerInfo.WordPress.DocRoot)

	var themes []models.WpPackage
	r := exec(l.ServerInfo, cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to get a list of WordPress plugins: %s", r)
	}
	err := json.Unmarshal([]byte(r.Stdout), &themes)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal wp theme list: %w", cmd, err)
	}
	for i := range themes {
		themes[i].Type = models.WPTheme
	}
	return themes, nil
}

func (l *base) detectWpPlugins() ([]models.WpPackage, error) {
	cmd := fmt.Sprintf("sudo -u %s -i -- %s plugin list --path=%s --format=json --allow-root",
		l.ServerInfo.WordPress.OSUser,
		l.ServerInfo.WordPress.CmdPath,
		l.ServerInfo.WordPress.DocRoot)

	var plugins []models.WpPackage
	r := exec(l.ServerInfo, cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to wp plugin list: %s", r)
	}
	if err := json.Unmarshal([]byte(r.Stdout), &plugins); err != nil {
		return nil, err
	}
	for i := range plugins {
		plugins[i].Type = models.WPPlugin
	}
	return plugins, nil
}

func (l *base) ps() (stdout string, err error) {
	cmd := `LANGUAGE=en_US.UTF-8 ps --no-headers --ppid 2 -p 2 --deselect -o pid,comm`
	r := l.exec(util.PrependProxyEnv(cmd), noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parsePs(stdout string) map[string]string {
	pidNames := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		ss := strings.Fields(line)
		if len(ss) < 2 {
			continue
		}
		pidNames[ss[0]] = ss[1]
	}
	return pidNames
}

func (l *base) lsProcExe(pid string) (stdout string, err error) {
	cmd := fmt.Sprintf("ls -l /proc/%s/exe", pid)
	r := l.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parseLsProcExe(stdout string) (string, error) {
	ss := strings.Fields(stdout)
	if len(ss) < 11 {
		return "", xerrors.Errorf("Unknown format: %s", stdout)
	}
	return ss[10], nil
}

func (l *base) grepProcMap(pid string) (stdout string, err error) {
	cmd := fmt.Sprintf(`cat /proc/%s/maps 2>/dev/null | grep -v " 00:00 " | awk '{print $6}' | sort -n | uniq`, pid)
	r := l.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parseGrepProcMap(stdout string) (soPaths []string) {
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		soPaths = append(soPaths, line)
	}
	return soPaths
}

func (l *base) lsOfListen() (stdout string, err error) {
	cmd := `lsof -i -P -n | grep LISTEN`
	r := l.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess(0, 1) {
		return "", xerrors.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parseLsOf(stdout string) map[string]string {
	portPid := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		ss := strings.Fields(scanner.Text())
		if len(ss) < 10 {
			continue
		}
		pid, ipPort := ss[1], ss[8]
		portPid[ipPort] = pid
	}
	return portPid
}
