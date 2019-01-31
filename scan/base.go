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

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"
)

type base struct {
	ServerInfo config.ServerInfo
	Distro     config.Distro
	Platform   models.Platform
	osPackages

	log  *logrus.Entry
	errs []error
}

func (l *base) scanWp() (err error) {
	if len(l.ServerInfo.WpPath) == 0 && len(l.ServerInfo.WpToken) == 0 {
		return nil
	}

	var unsecures []models.VulnInfo
	if unsecures, err = detectWp(l.ServerInfo); err != nil {
		l.log.Errorf("Failed to scan wordpress: %s", err)
		return err
	}
	for _, i := range unsecures {
		l.WpVulnInfos[i.CveID] = i
	}

	return
}

//WpCveInfos is for wpvulndb's json
type WpCveInfos struct {
	ReleaseDate     string      `json:"release_date"`
	ChangelogURL    string      `json:"changelog_url"`
	Status          string      `json:"status"`
	LatestVersion   string      `json:"latest_version"`
	LastUpdated     string      `json:"last_updated"`
	Popular         bool        `json:"popular"`
	Vulnerabilities []WpCveInfo `json:"vulnerabilities"`
	Error           string      `json:"error"`
}

//WpCveInfo is for wpvulndb's json
type WpCveInfo struct {
	ID            int        `json:"id"`
	Title         string     `json:"title"`
	CreatedAt     string     `json:"created_at"`
	UpdatedAt     string     `json:"updated_at"`
	PublishedDate string     `json:"Published_date"`
	VulnType      string     `json:"Vuln_type"`
	References    References `json:"references"`
	FixedIn       string     `json:"fixed_in"`
}

//References is for wpvulndb's json
type References struct {
	URL     []string `json:"url"`
	Cve     []string `json:"cve"`
	Secunia []string `json:"secunia"`
}

func detectWp(c config.ServerInfo) (rs []models.VulnInfo, err error) {

	var coreVuln []models.VulnInfo
	if coreVuln, err = detectWpCore(c); err != nil {
		return
	}
	for _, i := range coreVuln {
		rs = append(rs, i)
	}

	var themeVuln []models.VulnInfo
	if themeVuln, err = detectWpTheme(c); err != nil {
		return
	}
	for _, i := range themeVuln {
		rs = append(rs, i)
	}

	var pluginVuln []models.VulnInfo
	if pluginVuln, err = detectWpPlugin(c); err != nil {
		return
	}
	for _, i := range pluginVuln {
		rs = append(rs, i)
	}

	return
}

func detectWpCore(c config.ServerInfo) (rs []models.VulnInfo, err error) {
	cmd := fmt.Sprintf("wp core version --path=%s", c.WpPath)

	var coreVersion string
	if r := exec(c, cmd, noSudo); r.isSuccess() {
		tmp := strings.Split(r.Stdout, ".")
		coreVersion = strings.Join(tmp, "")
		coreVersion = strings.TrimRight(coreVersion, "\r\n")
		if len(coreVersion) == 0 {
			return
		}
	}
	cmd = fmt.Sprintf("curl -k -H 'Authorization: Token token=%s' https://wpvulndb.com/api/v3/wordpresses/%s", c.WpToken, coreVersion)
	if r := exec(c, cmd, noSudo); r.isSuccess() {
		data := map[string]WpCveInfos{}
		if err = json.Unmarshal([]byte(r.Stdout), &data); err != nil {
			return
		}
		for _, i := range data {
			if len(i.Vulnerabilities) == 0 {
				continue
			}
			for _, e := range i.Vulnerabilities {
				var cveIDs []string
				for _, k := range e.References.Cve {
					cveIDs = append(cveIDs, "CVE-"+k)
				}

				for _, cveID := range cveIDs {
					rs = append(rs, models.VulnInfo{
						CveID: cveID,
					})
				}
			}
		}
	}
	return
}

//WpStatus is for wp command
type WpStatus struct {
	Name    string `json:"-"`
	Status  string `json:"-"`
	Update  string `json:"-"`
	Version string `json:"-"`
}

func detectWpTheme(c config.ServerInfo) (rs []models.VulnInfo, err error) {
	cmd := fmt.Sprintf("wp theme list --path=%s", c.WpPath)

	var themes []WpStatus
	if r := exec(c, cmd, noSudo); r.isSuccess() {
		themes = parseStatus(r.Stdout)
	}

	for _, theme := range themes {
		cmd := fmt.Sprintf("curl -H 'Authorization: Token token=%s' https://wpvulndb.com/api/v3/themes/%s", c.WpToken, theme.Name)
		if r := exec(c, cmd, noSudo); r.isSuccess() {
			data := map[string]WpCveInfos{}
			if err = json.Unmarshal([]byte(r.Stdout), &data); err != nil {
				var jsonError WpCveInfos
				if err = json.Unmarshal([]byte(r.Stdout), &jsonError); err != nil {
					return
				}
				continue
			}
			for _, i := range data {
				if len(i.Vulnerabilities) == 0 {
					continue
				}
				if len(i.Error) != 0 {
					continue
				}
				for _, e := range i.Vulnerabilities {
					v1, _ := version.NewVersion(theme.Version)
					v2, _ := version.NewVersion(e.FixedIn)
					if v1.LessThan(v2) {
						if len(e.References.Cve) == 0 {
							continue
						}
						var cveIDs []string
						for _, k := range e.References.Cve {
							cveIDs = append(cveIDs, "CVE-"+k)
						}

						for _, cveID := range cveIDs {
							rs = append(rs, models.VulnInfo{
								CveID: cveID,
							})
						}
					}
				}
			}

		}
	}
	return
}

func detectWpPlugin(c config.ServerInfo) (rs []models.VulnInfo, err error) {
	cmd := fmt.Sprintf("wp plugin list --path=%s", c.WpPath)

	var plugins []WpStatus
	if r := exec(c, cmd, noSudo); r.isSuccess() {
		plugins = parseStatus(r.Stdout)
	}

	for _, plugin := range plugins {
		cmd := fmt.Sprintf("curl -H 'Authorization: Token token=%s' https://wpvulndb.com/api/v3/plugins/%s", c.WpToken, plugin.Name)

		if r := exec(c, cmd, noSudo); r.isSuccess() {
			data := map[string]WpCveInfos{}
			if err = json.Unmarshal([]byte(r.Stdout), &data); err != nil {
				var jsonError WpCveInfos
				if err = json.Unmarshal([]byte(r.Stdout), &jsonError); err != nil {
					return
				}
				continue
			}
			for _, i := range data {
				if len(i.Vulnerabilities) == 0 {
					continue
				}
				if len(i.Error) != 0 {
					continue
				}
				for _, e := range i.Vulnerabilities {
					v1, _ := version.NewVersion(plugin.Version)
					v2, _ := version.NewVersion(e.FixedIn)
					if v1.LessThan(v2) {
						if len(e.References.Cve) == 0 {
							continue
						}
						var cveIDs []string
						for _, k := range e.References.Cve {
							cveIDs = append(cveIDs, "CVE-"+k)
						}

						for _, cveID := range cveIDs {
							rs = append(rs, models.VulnInfo{
								CveID: cveID,
							})
						}
					}
				}
			}
		}
	}
	return
}

func parseStatus(r string) (themes []WpStatus) {
	tmp := strings.Split(r, "\r\n")
	tmp = unset(tmp, 0)
	tmp = unset(tmp, 0)
	tmp = unset(tmp, 0)
	tmp = unset(tmp, len(tmp)-1)
	tmp = unset(tmp, len(tmp)-1)
	for _, k := range tmp {
		theme := strings.Split(k, "|")
		themes = append(themes, WpStatus{
			Name:    strings.TrimSpace(theme[1]),
			Status:  strings.TrimSpace(theme[2]),
			Update:  strings.TrimSpace(theme[3]),
			Version: strings.TrimSpace(theme[4]),
		})
	}
	return
}

func unset(s []string, i int) []string {
	if i >= len(s) {
		return s
	}
	return append(s[:i], s[i+1:]...)
}

func (l *base) wpConvertToModel() models.VulnInfos {
	return l.WpVulnInfos
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
		return "", "", fmt.Errorf("Failed to SSH: %s", r)
	}
	release = strings.TrimSpace(r.Stdout)

	switch l.Distro.Family {
	case config.Debian:
		r := l.exec("uname -a", noSudo)
		if !r.isSuccess() {
			return "", "", fmt.Errorf("Failed to SSH: %s", r)
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
		return containers, fmt.Errorf(
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
		return containers, fmt.Errorf(
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
		return containers, fmt.Errorf(
			"Not supported yet: %s", l.ServerInfo.ContainerType)
	}
}

func (l *base) dockerPs(option string) (string, error) {
	cmd := fmt.Sprintf("docker ps %s", option)
	r := l.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", fmt.Errorf("Failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) lxdPs(option string) (string, error) {
	cmd := fmt.Sprintf("lxc list %s", option)
	r := l.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", fmt.Errorf("failed to SSH: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) lxcPs(option string) (string, error) {
	cmd := fmt.Sprintf("lxc-ls %s 2>/dev/null", option)
	r := l.exec(cmd, sudo)
	if !r.isSuccess() {
		return "", fmt.Errorf("failed to SSH: %s", r)
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
			return containers, fmt.Errorf("Unknown format: %s", line)
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
			return containers, fmt.Errorf("Unknown format: %s", line)
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
		return nil, nil, fmt.Errorf("Failed to detect IP address: %v", r)
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
	return false, "", fmt.Errorf(
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

	errs := []string{}
	for _, e := range l.errs {
		errs = append(errs, fmt.Sprintf("%s", e))
	}

	return models.ScanResult{
		JSONVersion:   models.JSONVersion,
		ServerName:    l.ServerInfo.ServerName,
		ScannedAt:     time.Now(),
		ScanMode:      l.ServerInfo.Mode.String(),
		Family:        l.Distro.Family,
		Release:       l.Distro.Release,
		Container:     container,
		Platform:      l.Platform,
		IPv4Addrs:     l.ServerInfo.IPv4Addrs,
		IPv6Addrs:     l.ServerInfo.IPv6Addrs,
		ScannedCves:   l.VulnInfos,
		RunningKernel: l.Kernel,
		Packages:      l.Packages,
		SrcPackages:   l.SrcPackages,
		Optional:      l.ServerInfo.Optional,
		Errors:        errs,
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
			return "", fmt.Errorf("Failed to stat %s: %s", cmd, r)
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
		return "", fmt.Errorf("Failed to detect a init system: %s", line)
	}
	return f("stat /proc/1/exe")
}

func (l *base) detectServiceName(pid string) (string, error) {
	cmd := fmt.Sprintf("systemctl status --quiet --no-pager %s", pid)
	r := l.exec(cmd, noSudo)
	if !r.isSuccess() {
		return "", fmt.Errorf("Failed to stat %s: %s", cmd, r)
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
