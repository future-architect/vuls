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
	"io/ioutil"
	"net/http"
)

type base struct {
	ServerInfo config.ServerInfo
	Distro     config.Distro
	Platform   models.Platform
	osPackages

	log  *logrus.Entry
	errs []error
}

//Command is for check dependence
type Command struct {
	Command string
	Name    string
}

func (l *base) scanWp() (err error) {
	if len(l.ServerInfo.WpPath) == 0 && len(l.ServerInfo.WpToken) == 0 {
		return nil
	}
	if len(l.ServerInfo.WpPath) == 0 {
		return fmt.Errorf("not found : WpPath")
	}
	if len(l.ServerInfo.WpToken) == 0 {
		return fmt.Errorf("not found : WpToken")
	}

	cmd := Command{Command: "wp cli", Name: "wp"}
	if r := exec(l.ServerInfo, cmd.Command, noSudo); !r.isSuccess() {
		return fmt.Errorf("%s command not installed", cmd.Name)
	}

	var vinfos []models.VulnInfo
	if vinfos, err = detectWp(l); err != nil {
		return fmt.Errorf("Failed to scan wordpress: %s", err)
	}
	l.WpVulnInfos = map[string]models.VulnInfo{}
	for _, vinfo := range vinfos {
		l.WpVulnInfos[vinfo.CveID] = vinfo
	}

	return nil
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
	PublishedDate string     `json:"published_date"`
	VulnType      string     `json:"vuln_type"`
	References    References `json:"references"`
	FixedIn       string     `json:"fixed_in"`
}

//References is for wpvulndb's json
type References struct {
	URL     []string `json:"url"`
	Cve     []string `json:"cve"`
	Secunia []string `json:"secunia"`
}

func detectWp(c *base) (vinfos []models.VulnInfo, err error) {
	var coreVulns []models.VulnInfo
	if coreVulns, err = detectWpCore(c); err != nil {
		return nil, err
	}
	vinfos = append(vinfos, coreVulns...)

	var themeVulns []models.VulnInfo
	if themeVulns, err = detectWpTheme(c); err != nil {
		return nil, err
	}
	vinfos = append(vinfos, themeVulns...)

	var pluginVulns []models.VulnInfo
	if pluginVulns, err = detectWpPlugin(c); err != nil {
		return nil, err
	}
	vinfos = append(vinfos, pluginVulns...)

	return vinfos, nil
}

func detectWpCore(c *base) (vinfos []models.VulnInfo, err error) {
	cmd := fmt.Sprintf("wp core version --path=%s", c.ServerInfo.WpPath)

	var coreVersion string
	var r execResult
	if r = exec(c.ServerInfo, cmd, noSudo); !r.isSuccess() {
		return nil, fmt.Errorf("%s", cmd)
	}
	tmpCoreVersion := strings.Split(r.Stdout, ".")
	coreVersion = strings.Join(tmpCoreVersion, "")
	coreVersion = strings.TrimRight(coreVersion, "\r\n")
	if len(coreVersion) == 0 {
		return nil, fmt.Errorf("version empty")
	}

	url := fmt.Sprintf("https://wpvulndb.com/api/v3/wordpresses/%s", coreVersion)
	var body []byte
	if body, err = httpRequest(c, WpStatus{}, url); err != nil {
		return nil, err
	}
	if vinfos, err = coreConvertVinfos(string(body)); err != nil {
		return nil, err
	}
	return vinfos, nil
}

func coreConvertVinfos(stdout string) (vinfos []models.VulnInfo, err error) {
	data := map[string]WpCveInfos{}
	if err = json.Unmarshal([]byte(stdout), &data); err != nil {
		var jsonError WpCveInfos
		if err = json.Unmarshal([]byte(stdout), &jsonError); err != nil {
			return nil, err
		}
	}
	for _, e := range data {
		if len(e.Vulnerabilities) == 0 {
			continue
		}
		for _, vulnerability := range e.Vulnerabilities {
			if len(vulnerability.References.Cve) == 0 {
				continue
			}
			notFixedYet := false
			if len(vulnerability.FixedIn) == 0 {
				notFixedYet = true
			}
			var cveIDs []string
			for _, cveNumber := range vulnerability.References.Cve {
				cveIDs = append(cveIDs, "CVE-"+cveNumber)
			}

			for _, cveID := range cveIDs {
				vinfos = append(vinfos, models.VulnInfo{
					CveID: cveID,
					CveContents: models.NewCveContents(
						models.CveContent{
							CveID: cveID,
							Title: vulnerability.Title,
						},
					),
					AffectedPackages: models.PackageStatuses{
						{
							NotFixedYet: notFixedYet,
						},
					},
				})
			}
		}
	}
	return vinfos, nil
}

//WpStatus is for wp command
type WpStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Update  string `json:"update"`
	Version string `json:"version"`
}

func detectWpTheme(c *base) (vinfos []models.VulnInfo, err error) {
	cmd := fmt.Sprintf("wp theme list --path=%s --format=json", c.ServerInfo.WpPath)

	var themes []WpStatus
	var r execResult
	if r = exec(c.ServerInfo, cmd, noSudo); !r.isSuccess() {
		return nil, fmt.Errorf("%s", cmd)
	}
	if err = json.Unmarshal([]byte(r.Stdout), &themes); err != nil {
		return nil, err
	}

	for _, theme := range themes {
		url := fmt.Sprintf("https://wpvulndb.com/api/v3/themes/%s", theme.Name)
		var body []byte
		if body, err = httpRequest(c, theme, url); err != nil {
			return nil, err
		}
		tmpVinfos, err := contentConvertVinfos(string(body), theme)
		if err != nil {
			return nil, err
		}
		vinfos = append(vinfos, tmpVinfos...)
	}
	return vinfos, nil
}

func detectWpPlugin(c *base) (vinfos []models.VulnInfo, err error) {
	cmd := fmt.Sprintf("wp plugin list --path=%s --format=json", c.ServerInfo.WpPath)

	var plugins []WpStatus
	var r execResult
	if r := exec(c.ServerInfo, cmd, noSudo); r.isSuccess() {
		if err = json.Unmarshal([]byte(r.Stdout), &plugins); err != nil {
			return nil, err
		}
	}
	if !r.isSuccess() {
		return nil, fmt.Errorf("%s", cmd)
	}

	for _, plugin := range plugins {
		url := fmt.Sprintf("https://wpvulndb.com/api/v3/plugins/%s", plugin.Name)
		var body []byte
		if body, err = httpRequest(c, plugin, url); err != nil {
			return nil, err
		}
		tmpVinfos, err := contentConvertVinfos(string(body), plugin)
		if err != nil {
			return nil, err
		}
		vinfos = append(vinfos, tmpVinfos...)
	}
	return vinfos, nil
}

func httpRequest(c *base, content WpStatus, url string) (body []byte, err error) {
	token := fmt.Sprintf("Token token=%s", c.ServerInfo.WpToken)
	var req *http.Request
	req, err = http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", token)
	client := new(http.Client)
	var resp *http.Response
	resp, err = client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 404 {
		return nil, fmt.Errorf("status: %s", resp.Status)
	} else if resp.StatusCode == 404 {
		var jsonError WpCveInfos
		if err = json.Unmarshal(body, &jsonError); err != nil {
			return nil, err
		}
		if jsonError.Error == "HTTP Token: Access denied.\n" {
			return nil, fmt.Errorf("wordpress: HTTP Token: Access denied")
		} else if jsonError.Error == "Not found" {
			c.log.Infof("wordpress: %s not found", content.Name)
		} else {
			return nil, fmt.Errorf("status: %s", resp.Status)
		}
	}
	return body, nil
}

func contentConvertVinfos(stdout string, content WpStatus) (vinfos []models.VulnInfo, err error) {
	data := map[string]WpCveInfos{}
	if err = json.Unmarshal([]byte(stdout), &data); err != nil {
		var jsonError WpCveInfos
		if err = json.Unmarshal([]byte(stdout), &jsonError); err != nil {
			return nil, err
		}
	}

	for _, e := range data {
		if len(e.Vulnerabilities) == 0 {
			continue
		}
		for _, vulnerability := range e.Vulnerabilities {
			if len(vulnerability.References.Cve) == 0 {
				continue
			}

			var cveIDs []string
			for _, cveNumber := range vulnerability.References.Cve {
				cveIDs = append(cveIDs, "CVE-"+cveNumber)
			}

			if len(vulnerability.FixedIn) == 0 {
				for _, cveID := range cveIDs {
					vinfos = append(vinfos, models.VulnInfo{
						CveID: cveID,
						CveContents: models.NewCveContents(
							models.CveContent{
								CveID: cveID,
								Title: vulnerability.Title,
							},
						),
						AffectedPackages: models.PackageStatuses{
							{
								NotFixedYet: true,
							},
						},
					})
				}
			}
			var v1 *version.Version
			v1, err = version.NewVersion(content.Version)
			if err != nil {
				return nil, err
			}
			var v2 *version.Version
			v2, err = version.NewVersion(vulnerability.FixedIn)
			if err != nil {
				return nil, err
			}
			if v1.LessThan(v2) {
				for _, cveID := range cveIDs {
					vinfos = append(vinfos, models.VulnInfo{
						CveID: cveID,
						CveContents: models.NewCveContents(
							models.CveContent{
								CveID: cveID,
								Title: vulnerability.Title,
							},
						),
						AffectedPackages: models.PackageStatuses{
							{
								NotFixedYet: false,
							},
						},
					})
				}
			}
		}
	}
	return vinfos, nil
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
