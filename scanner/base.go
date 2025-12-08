package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	fanal "github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	tlog "github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	xio "github.com/aquasecurity/trivy/pkg/x/io"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ufilepath "github.com/future-architect/vuls/scanner/utils/filepath/unix"
	"github.com/future-architect/vuls/util"

	// Import library scanner
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/c/conan"
	// Conda package is supported for SBOM, not for vulnerability scanning
	// https://github.com/aquasecurity/trivy/blob/v0.49.1/pkg/detector/library/driver.go#L75-L77
	// _ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/conda/meta"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dart/pub"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/deps"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/nuget"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/packagesprops"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/elixir/mix"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/mod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/gradle"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"

	// Julia is supported for SBOM, not for vulnerability scanning
	// https://github.com/aquasecurity/trivy/blob/v0.52.0/pkg/detector/library/driver.go#L84-L86
	// _ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/julia/pkg"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/bun"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/npm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pnpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/yarn"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pipenv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/poetry"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/uv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/cargo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/swift/cocoapods"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/swift/swift"

	// Excleded ones:
	// Trivy can parse package.json but doesn't use dependencies info. Not use here
	// _ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pkg"
	// No dependency information included
	// _ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/gemspec"
	// No dependency information included
	// _ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/packaging"

	nmap "github.com/Ullaakut/nmap/v2"

	// To avoid downloading Java DB at scan phase, use custom one for JAR files
	_ "github.com/future-architect/vuls/scanner/trivy/jar"
	// _ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/jar"
)

type base struct {
	ServerInfo config.ServerInfo
	Distro     config.Distro
	Platform   models.Platform
	osPackages
	LibraryScanners []models.LibraryScanner
	WordPress       models.WordPressPackages
	windowsKB       *models.WindowsKB

	log   logging.Logger
	errs  []error
	warns []error
}

// osPackages is included by base struct
type osPackages struct {
	// installed packages
	Packages models.Packages

	// installed source packages (Debian based only)
	SrcPackages models.SrcPackages

	// Detected Vulnerabilities Key: CVE-ID
	VulnInfos models.VulnInfos

	// kernel information
	Kernel models.Kernel
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
	case constant.Debian:
		r := l.exec(fmt.Sprintf("dpkg-query -W -f='${Version}' linux-image-%s", release), noSudo)
		if !r.isSuccess() {
			l.log.Debugf("Failed to get the running kernel version. err: %s", r.Stderr)
			return release, "", nil
		}
		return release, r.Stdout, nil
	default:
		return release, "", nil
	}
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
		fields := strings.Fields(strings.ReplaceAll(line, "|", " "))
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

// parseIfconfig parses the results of ifconfig command
func (l *base) parseIfconfig(stdout string) (ipv4Addrs []string, ipv6Addrs []string) {
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 4 || !strings.HasPrefix(fields[0], "inet") {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
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
}

var dsFingerPrintPrefix = "AgentStatus.agentCertHash: "

func (l *base) detectDeepSecurity() (string, error) {
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

func (l *base) detectIPS() {
	ips := map[string]string{}
	fingerprint, err := l.detectDeepSecurity()
	if err != nil {
		return
	}
	ips[constant.DeepSecurity] = fingerprint
	l.ServerInfo.IPSIdentifiers = ips
}

func (l *base) detectRunningOnAws() (ok bool, instanceID string, err error) {
	if r := l.exec("type curl", noSudo); r.isSuccess() {
		cmd := "curl --max-time 1 --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/instance-id"
		r := l.exec(cmd, noSudo)
		if r.isSuccess() {
			id := strings.TrimSpace(r.Stdout)
			if l.isAwsInstanceID(id) {
				return true, id, nil
			}
		}

		cmd = "curl -X PUT --max-time 1 --noproxy 169.254.169.254 -H \"X-aws-ec2-metadata-token-ttl-seconds: 300\" http://169.254.169.254/latest/api/token"
		r = l.exec(cmd, noSudo)
		if r.isSuccess() {
			token := strings.TrimSpace(r.Stdout)
			cmd = fmt.Sprintf("curl -H \"X-aws-ec2-metadata-token: %s\" --max-time 1 --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/instance-id", token)
			r = l.exec(cmd, noSudo)
			if r.isSuccess() {
				id := strings.TrimSpace(r.Stdout)
				if !l.isAwsInstanceID(id) {
					return false, "", nil
				}
				return true, id, nil
			}
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
	} else if l.ServerInfo.Type == constant.ServerTypePseudo {
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
		WindowsKB:         l.windowsKB,
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

func (l *base) setLogger(logger logging.Logger) {
	l.log = logger
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

var trivyLoggerInit = sync.OnceFunc(func() { tlog.InitLogger(config.Conf.Debug, config.Conf.Quiet) })

func (l *base) scanLibraries() (err error) {
	if len(l.LibraryScanners) > 0 {
		return nil
	}

	// library scan for servers need lockfiles
	if len(l.ServerInfo.Lockfiles) == 0 && !l.ServerInfo.FindLock {
		return nil
	}

	l.log.Info("Scanning Language-specific Packages...")

	trivyLoggerInit()

	detectFiles := l.ServerInfo.Lockfiles

	priv := noSudo
	if l.getServerInfo().Mode.IsFastRoot() || l.getServerInfo().Mode.IsDeep() {
		priv = sudo
	}

	// auto detect lockfile
	if l.ServerInfo.FindLock {
		dir := func() string {
			if len(l.ServerInfo.FindLockDirs) == 0 {
				l.log.Infof("It's recommended to specify FindLockDirs in config.toml. If FindLockDirs is not specified, all directories under / will be searched, which may increase CPU load")
				return "/"
			}
			return strings.Join(l.ServerInfo.FindLockDirs, " ")
		}()

		findopt := func() string {
			ss := make([]string, 0, len(models.FindLockFiles))
			for _, filename := range models.FindLockFiles {
				ss = append(ss, fmt.Sprintf("-name %q", filename))
			}
			return strings.Join(ss, " -o ")
		}()

		l.log.Infof("Finding files under %s", dir)

		// find / -type f -and \( -name "package-lock.json" -o -name "yarn.lock" ... \) 2>&1 | grep -v "find: "
		r := l.exec(fmt.Sprintf(`find %s -type f -and \( %s \) 2>&1 | grep -v "find: "`, dir, findopt), priv)
		if r.ExitStatus != 0 && r.ExitStatus != 1 {
			return xerrors.Errorf("Failed to find lock files: %s", r)
		}

		scanner := bufio.NewScanner(strings.NewReader(r.Stdout))
		for scanner.Scan() {
			detectFiles = append(detectFiles, scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			return xerrors.Errorf("Failed to reading find results. err: %w", err)
		}
	}

	found := make(map[string]bool)
	for _, path := range detectFiles {
		if path == "" {
			continue
		}

		abspath, err := func() (string, error) {
			if ufilepath.IsAbs(path) {
				return ufilepath.Clean(path), nil
			}

			r := l.exec("pwd", noSudo)
			if !r.isSuccess() {
				return "", xerrors.Errorf("Failed to get current directory. err: %w", r.Error)
			}

			return ufilepath.Join(strings.TrimSuffix(r.Stdout, "\n"), path), nil
		}()
		if err != nil {
			return xerrors.Errorf("Failed to abs the lockfile. filepath: %s, err: %w", path, err)
		}

		if _, ok := found[abspath]; ok {
			continue
		}
		found[abspath] = true

		l.log.Debugf("Analyzing file: %s", abspath)
		filemode, contents, err := func() (os.FileMode, []byte, error) {
			r := l.exec(fmt.Sprintf(`stat -c "%%a" %s`, abspath), priv)
			if !r.isSuccess() {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to get target file permission. filepath: %s, err: %w", abspath, err)
			}
			permStr := fmt.Sprintf("0%s", strings.TrimSuffix(r.Stdout, "\n"))
			perm, err := strconv.ParseUint(permStr, 8, 32)
			if err != nil {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to parse permission string. , permission string: %s, err: %s", permStr, err)
			}
			filemode := os.FileMode(perm)

			r = l.exec(fmt.Sprintf("cat %s", abspath), priv)
			if !r.isSuccess() {
				return os.FileMode(0000), nil, xerrors.Errorf("Failed to read target file contents. filepath: %s, err: %w", abspath, err)
			}
			contents := []byte(r.Stdout)

			return filemode, contents, nil
		}()
		if err != nil {
			l.log.Warn(err)
			continue
		}

		libraryScanners, err := AnalyzeLibrary(context.Background(), abspath, contents, filemode, l.ServerInfo.Mode.IsOffline())
		if err != nil {
			return xerrors.Errorf("Failed to analyze library. err: %w, filepath: %s", err, abspath)
		}
		l.LibraryScanners = append(l.LibraryScanners, libraryScanners...)
	}
	return nil
}

// AnalyzeLibrary : detects library defined in artifact such as lockfile or jar
func AnalyzeLibrary(ctx context.Context, path string, contents []byte, filemode os.FileMode, isOffline bool) (libraryScanners []models.LibraryScanner, err error) {
	ag, err := fanal.NewAnalyzerGroup(fanal.AnalyzerOptions{
		Group:             fanal.GroupBuiltin,
		DisabledAnalyzers: disabledAnalyzers,
	})
	if err != nil {
		return nil, xerrors.Errorf("Failed to new analyzer group. err: %w", err)
	}

	// `errgroup` cancels the context after Wait returns, so it can’t be use later.
	// We need a separate context specifically for Analyze.
	eg, egCtx := errgroup.WithContext(ctx)
	result := fanal.NewAnalysisResult()

	info := &DummyFileInfo{name: ufilepath.Base(path), size: int64(len(contents)), filemode: filemode}
	opts := fanal.AnalysisOptions{Offline: isOffline}
	if err := ag.AnalyzeFile(
		egCtx,
		eg,
		semaphore.New(1),
		result,
		"",
		path,
		info,
		func() (xio.ReadSeekCloserAt, error) { return xio.NopCloser(bytes.NewReader(contents)), nil },
		nil,
		opts,
	); err != nil {
		return nil, xerrors.Errorf("Failed to get libs. err: %w", err)
	}

	if err = eg.Wait(); err != nil {
		return nil, xerrors.Errorf("analyze error: %w", err)
	}

	// Post-analysis
	composite, err := ag.PostAnalyzerFS()
	if err != nil {
		return nil, xerrors.Errorf("Failed to prepare filesystem for post-analysis. err: %w", err)
	}
	defer func() {
		_ = composite.Cleanup()
	}()

	analyzerTypes := ag.RequiredPostAnalyzers(path, info)
	if len(analyzerTypes) != 0 {
		opener := func() (xio.ReadSeekCloserAt, error) { return xio.NopCloser(bytes.NewReader(contents)), nil }
		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return nil, xerrors.Errorf("Failed to copy file to temp. err: %w", err)
		}
		if err := composite.CreateLink(analyzerTypes, "", path, tmpFilePath); err != nil {
			return nil, xerrors.Errorf("Failed to create link. err: %w", err)
		}
		if err = ag.PostAnalyze(ctx, composite, result, opts); err != nil {
			return nil, xerrors.Errorf("Failed at post-analysis. err: %w", err)
		}
	}

	libscan, err := convertLibWithScanner(result.Applications)
	if err != nil {
		return nil, xerrors.Errorf("Failed to convert libs. err: %w", err)
	}
	libraryScanners = append(libraryScanners, libscan...)
	return libraryScanners, nil
}

// https://github.com/aquasecurity/trivy/blob/v0.49.1/pkg/fanal/analyzer/const.go
var disabledAnalyzers = []fanal.Type{
	// ======
	//   OS
	// ======
	fanal.TypeOSRelease,
	fanal.TypeAlpine,
	fanal.TypeAmazon,
	fanal.TypeAzure,
	fanal.TypeCBLMariner,
	fanal.TypeDebian,
	fanal.TypePhoton,
	fanal.TypeCentOS,
	fanal.TypeRocky,
	fanal.TypeAlma,
	fanal.TypeFedora,
	fanal.TypeOracle,
	fanal.TypeRedHatBase,
	fanal.TypeSUSE,
	fanal.TypeUbuntu,
	fanal.TypeUbuntuESM,
	fanal.TypeCoreOS,

	// OS Package
	fanal.TypeApk,
	fanal.TypeDpkg,
	fanal.TypeDpkgLicense,
	fanal.TypeRpm,
	fanal.TypeRpmqa,

	// OS Package Repository
	fanal.TypeApkRepo,

	// ============
	// Non-packaged
	// ============
	fanal.TypeExecutable,
	fanal.TypeSBOM,

	// ============
	// Image Config
	// ============
	fanal.TypeApkCommand,
	fanal.TypeHistoryDockerfile,
	fanal.TypeImageConfigSecret,

	// =================
	// Structured Config
	// =================
	fanal.TypeAzureARM,
	fanal.TypeCloudFormation,
	fanal.TypeDockerfile,
	fanal.TypeHelm,
	fanal.TypeKubernetes,
	fanal.TypeTerraform,
	fanal.TypeTerraformPlanJSON,
	fanal.TypeTerraformPlanSnapshot,

	// ========
	// License
	// ========
	fanal.TypeLicenseFile,

	// ========
	// Secrets
	// ========
	fanal.TypeSecret,

	// =======
	// Red Hat
	// =======
	fanal.TypeRedHatContentManifestType,
	fanal.TypeRedHatDockerfileType,
}

// DummyFileInfo is a dummy struct for libscan
type DummyFileInfo struct {
	name     string
	size     int64
	filemode os.FileMode
}

// Name is
func (d *DummyFileInfo) Name() string { return d.name }

// Size is
func (d *DummyFileInfo) Size() int64 { return d.size }

// Mode is
func (d *DummyFileInfo) Mode() os.FileMode { return d.filemode }

// ModTime is
func (d *DummyFileInfo) ModTime() time.Time { return time.Now() }

// IsDir is
func (d *DummyFileInfo) IsDir() bool { return false }

// Sys is
func (d *DummyFileInfo) Sys() interface{} { return nil }

func (l *base) buildWpCliCmd(wpCliArgs string, suppressStderr bool, shell string) string {
	cmd := fmt.Sprintf("%s %s --path=%s", l.ServerInfo.WordPress.CmdPath, wpCliArgs, l.ServerInfo.WordPress.DocRoot)
	if !l.ServerInfo.WordPress.NoSudo {
		cmd = fmt.Sprintf("sudo -u %s -i -- %s --allow-root", l.ServerInfo.WordPress.OSUser, cmd)
	} else if l.ServerInfo.User != l.ServerInfo.WordPress.OSUser {
		cmd = fmt.Sprintf("su %s -c '%s'", l.ServerInfo.WordPress.OSUser, cmd)
	}

	if suppressStderr {
		switch shell {
		case "csh", "tcsh":
			cmd = fmt.Sprintf("( %s > /dev/tty ) >& /dev/null", cmd)
		default:
			cmd = fmt.Sprintf("%s 2>/dev/null", cmd)
		}
	}
	return cmd
}

func (l *base) scanWordPress() error {
	if l.ServerInfo.WordPress.IsZero() || l.ServerInfo.Type == constant.ServerTypePseudo {
		return nil
	}

	shell, err := l.detectShell()
	if err != nil {
		return xerrors.Errorf("Failed to detect shell. err: %w", err)
	}

	l.log.Info("Scanning WordPress...")
	if l.ServerInfo.WordPress.NoSudo && l.ServerInfo.User != l.ServerInfo.WordPress.OSUser {
		if r := l.exec(fmt.Sprintf("timeout 2 su %s -c exit", l.ServerInfo.WordPress.OSUser), noSudo); !r.isSuccess() {
			return xerrors.New("Failed to switch user without password. err: please configure to switch users without password")
		}
	}

	cmd := l.buildWpCliCmd("core version", false, shell)
	if r := exec(l.ServerInfo, cmd, noSudo); !r.isSuccess() {
		return xerrors.Errorf("Failed to exec `%s`. Check the OS user, command path of wp-cli, DocRoot and permission: %#v", cmd, l.ServerInfo.WordPress)
	}

	wp, err := l.detectWordPress(shell)
	if err != nil {
		return xerrors.Errorf("Failed to scan wordpress: %w", err)
	}
	l.WordPress = *wp
	return nil
}

func (l *base) detectShell() (string, error) {
	if r := l.exec("printenv SHELL", noSudo); r.isSuccess() {
		if t := strings.TrimSpace(r.Stdout); t != "" {
			return filepath.Base(t), nil
		}
	}

	if r := l.exec(fmt.Sprintf(`grep "^%s" /etc/passwd | awk -F: '/%s/ { print $7 }'`, l.ServerInfo.User, l.ServerInfo.User), noSudo); r.isSuccess() {
		if t := strings.TrimSpace(r.Stdout); t != "" {
			return filepath.Base(t), nil
		}
	}

	if isLocalExec(l.ServerInfo.Port, l.ServerInfo.Host) {
		if r := l.exec("ps -p $$ | tail +2 | awk '{print $NF}'", noSudo); r.isSuccess() {
			return strings.TrimSpace(r.Stdout), nil
		}

		if r := l.exec("ps -p %self | tail +2 | awk '{print $NF}'", noSudo); r.isSuccess() {
			return strings.TrimSpace(r.Stdout), nil
		}
	}

	return "", xerrors.New("shell cannot be determined")
}

func (l *base) detectWordPress(shell string) (*models.WordPressPackages, error) {
	ver, err := l.detectWpCore(shell)
	if err != nil {
		return nil, err
	}

	themes, err := l.detectWpThemes(shell)
	if err != nil {
		return nil, err
	}

	plugins, err := l.detectWpPlugins(shell)
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

func (l *base) detectWpCore(shell string) (string, error) {
	cmd := l.buildWpCliCmd("core version", true, shell)

	r := exec(l.ServerInfo, cmd, noSudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to get wp core version: %s", r)
	}
	return strings.TrimSpace(r.Stdout), nil
}

func (l *base) detectWpThemes(shell string) ([]models.WpPackage, error) {
	cmd := l.buildWpCliCmd("theme list --format=json", true, shell)

	var themes []models.WpPackage
	r := exec(l.ServerInfo, cmd, noSudo)
	if !r.isSuccess() {
		return nil, xerrors.Errorf("Failed to get a list of WordPress plugins: %s", r)
	}
	err := json.Unmarshal([]byte(r.Stdout), &themes)
	if err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal wp theme list: %w", err)
	}
	for i := range themes {
		themes[i].Type = models.WPTheme
	}
	return themes, nil
}

func (l *base) detectWpPlugins(shell string) ([]models.WpPackage, error) {
	cmd := l.buildWpCliCmd("plugin list --format=json", true, shell)

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

func (l *base) scanPorts() (err error) {
	l.log.Info("Scanning listen port...")
	dest := l.detectScanDest()
	open, err := l.execPortsScan(dest)
	if err != nil {
		return err
	}
	l.updatePortStatus(open)

	return nil
}

func (l *base) detectScanDest() map[string][]string {
	scanIPPortsMap := map[string][]string{}

	for _, p := range l.Packages {
		if p.AffectedProcs == nil {
			continue
		}
		for _, proc := range p.AffectedProcs {
			if proc.ListenPortStats == nil {
				continue
			}
			for _, port := range proc.ListenPortStats {
				scanIPPortsMap[port.BindAddress] = append(scanIPPortsMap[port.BindAddress], port.Port)
			}
		}
	}

	scanDestIPPorts := map[string][]string{}
	for addr, ports := range scanIPPortsMap {
		if addr == "*" {
			for _, addr := range l.ServerInfo.IPv4Addrs {
				scanDestIPPorts[addr] = append(scanDestIPPorts[addr], ports...)
			}
		} else {
			scanDestIPPorts[addr] = append(scanDestIPPorts[addr], ports...)
		}
	}

	uniqScanDestIPPorts := map[string][]string{}
	for i, scanDest := range scanDestIPPorts {
		m := map[string]bool{}
		for _, e := range scanDest {
			if !m[e] {
				m[e] = true
				uniqScanDestIPPorts[i] = append(uniqScanDestIPPorts[i], e)
			}
		}
	}

	return uniqScanDestIPPorts
}

func (l *base) execPortsScan(scanDestIPPorts map[string][]string) ([]string, error) {
	if l.getServerInfo().PortScan.IsUseExternalScanner {
		listenIPPorts, err := l.execExternalPortScan(scanDestIPPorts)
		if err != nil {
			return []string{}, err
		}
		return listenIPPorts, nil
	}

	listenIPPorts, err := l.execNativePortScan(scanDestIPPorts)
	if err != nil {
		return []string{}, err
	}

	return listenIPPorts, nil
}

func (l *base) execNativePortScan(scanDestIPPorts map[string][]string) ([]string, error) {
	l.log.Info("Using Port Scanner: Vuls built-in Scanner")

	listenIPPorts := []string{}

	for ip, ports := range scanDestIPPorts {
		if !isLocalExec(l.ServerInfo.Port, l.ServerInfo.Host) && net.ParseIP(ip).IsLoopback() {
			continue
		}

		for _, port := range ports {
			scanDest := ip + ":" + port
			isOpen, err := nativeScanPort(scanDest)
			if err != nil {
				return []string{}, err
			}

			if isOpen {
				listenIPPorts = append(listenIPPorts, scanDest)
			}
		}
	}

	return listenIPPorts, nil
}

func nativeScanPort(scanDest string) (bool, error) {
	conn, err := net.DialTimeout("tcp", scanDest, time.Duration(1)*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "connection refused") {
			return false, nil
		}
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(time.Duration(1) * time.Second)
			return nativeScanPort(scanDest)
		}
		return false, err
	}
	if err := conn.Close(); err != nil {
		return false, xerrors.Errorf("Failed to close connection. err: %w", err)
	}

	return true, nil
}

func (l *base) execExternalPortScan(scanDestIPPorts map[string][]string) ([]string, error) {
	portScanConf := l.getServerInfo().PortScan
	l.log.Infof("Using Port Scanner: External Scanner(PATH: %s)", portScanConf.ScannerBinPath)
	l.log.Infof("External Scanner Apply Options: Scan Techniques: %s, HasPrivileged: %t, Source Port: %s",
		strings.Join(portScanConf.ScanTechniques, ","), portScanConf.HasPrivileged, portScanConf.SourcePort)
	baseCmd := formatNmapOptionsToString(portScanConf)

	listenIPPorts := []string{}

	for ip, ports := range scanDestIPPorts {
		if !isLocalExec(l.ServerInfo.Port, l.ServerInfo.Host) && net.ParseIP(ip).IsLoopback() {
			continue
		}

		_, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		scanner, err := nmap.NewScanner(nmap.WithBinaryPath(portScanConf.ScannerBinPath))
		if err != nil {
			return []string{}, xerrors.Errorf("unable to create nmap scanner: %w", err)
		}

		scanTechnique, err := l.setScanTechniques()
		if err != nil {
			return []string{}, err
		}
		scanner.AddOptions(scanTechnique)

		if portScanConf.HasPrivileged {
			scanner.AddOptions(nmap.WithPrivileged())
		} else {
			scanner.AddOptions(nmap.WithUnprivileged())
		}

		if portScanConf.SourcePort != "" {
			port, err := strconv.ParseUint(portScanConf.SourcePort, 10, 16)
			if err != nil {
				return []string{}, xerrors.Errorf("failed to strconv.ParseUint(%s, 10, 16) = %w", portScanConf.SourcePort, err)
			}
			scanner.AddOptions(nmap.WithSourcePort(uint16(port)))
		}

		cmd := []string{baseCmd}
		if strings.Contains(ip, ":") {
			scanner.AddOptions(nmap.WithTargets(ip[1:len(ip)-1]), nmap.WithPorts(ports...), nmap.WithIPv6Scanning())
			cmd = append(cmd, "-p", strings.Join(ports, ","), ip[1:len(ip)-1])
		} else {
			scanner.AddOptions(nmap.WithTargets(ip), nmap.WithPorts(ports...))
			cmd = append(cmd, "-p", strings.Join(ports, ","), ip)
		}

		l.log.Debugf("Executing... %s", strings.ReplaceAll(strings.Join(cmd, " "), "\n", ""))
		result, warnings, err := scanner.Run()
		if err != nil {
			return []string{}, xerrors.Errorf("unable to run nmap scan: %w", err)
		}

		if warnings != nil {
			l.log.Warnf("nmap scan warnings: %s", warnings)
		}

		for _, host := range result.Hosts {
			if len(host.Ports) == 0 || len(host.Addresses) == 0 {
				continue
			}

			for _, port := range host.Ports {
				if strings.Contains(string(port.Status()), string(nmap.Open)) {
					scanDest := fmt.Sprintf("%s:%d", ip, port.ID)
					listenIPPorts = append(listenIPPorts, scanDest)
				}
			}
		}
	}

	return listenIPPorts, nil
}

func formatNmapOptionsToString(conf *config.PortScanConf) string {
	cmd := []string{conf.ScannerBinPath}
	for _, technique := range conf.ScanTechniques {
		cmd = append(cmd, "-"+technique)
	}

	if conf.SourcePort != "" {
		cmd = append(cmd, "--source-port "+conf.SourcePort)
	}

	if conf.HasPrivileged {
		cmd = append(cmd, "--privileged")
	}

	return strings.Join(cmd, " ")
}

func (l *base) setScanTechniques() (func(*nmap.Scanner), error) {
	scanTechniques := l.getServerInfo().PortScan.GetScanTechniques()

	if len(scanTechniques) == 0 {
		if l.getServerInfo().PortScan.HasPrivileged {
			return nmap.WithSYNScan(), nil
		}
		return nmap.WithConnectScan(), nil
	}

	for _, technique := range scanTechniques {
		switch technique {
		case config.TCPSYN:
			return nmap.WithSYNScan(), nil
		case config.TCPConnect:
			return nmap.WithConnectScan(), nil
		case config.TCPACK:
			return nmap.WithACKScan(), nil
		case config.TCPWindow:
			return nmap.WithWindowScan(), nil
		case config.TCPMaimon:
			return nmap.WithMaimonScan(), nil
		case config.TCPNull:
			return nmap.WithTCPNullScan(), nil
		case config.TCPFIN:
			return nmap.WithTCPFINScan(), nil
		case config.TCPXmas:
			return nmap.WithTCPXmasScan(), nil
		}
	}

	return nil, xerrors.Errorf("Failed to setScanTechniques. There is an unsupported option in ScanTechniques.")
}

func (l *base) updatePortStatus(listenIPPorts []string) {
	for name, p := range l.Packages {
		if p.AffectedProcs == nil {
			continue
		}
		for i, proc := range p.AffectedProcs {
			if proc.ListenPortStats == nil {
				continue
			}
			for j, port := range proc.ListenPortStats {
				l.Packages[name].AffectedProcs[i].ListenPortStats[j].PortReachableTo = l.findPortTestSuccessOn(listenIPPorts, port)
			}
		}
	}
}

func (l *base) findPortTestSuccessOn(listenIPPorts []string, searchListenPort models.PortStat) []string {
	addrs := []string{}

	for _, ipPort := range listenIPPorts {
		ipPort, err := models.NewPortStat(ipPort)
		if err != nil {
			l.log.Warnf("Failed to find: %+v", err)
			continue
		}
		if searchListenPort.BindAddress == "*" {
			if searchListenPort.Port == ipPort.Port {
				addrs = append(addrs, ipPort.BindAddress)
			}
		} else if searchListenPort.BindAddress == ipPort.BindAddress && searchListenPort.Port == ipPort.Port {
			addrs = append(addrs, ipPort.BindAddress)
		}
	}

	return addrs
}

func (l *base) ps() (string, error) {
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

func (l *base) lsProcExe(pid string) (string, error) {
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

func (l *base) grepProcMap(pid string) (string, error) {
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
		line = strings.Split(line, ";")[0]
		soPaths = append(soPaths, line)
	}
	return soPaths
}

func (l *base) lsOfListen() (string, error) {
	cmd := `lsof -i -P -n`
	r := l.exec(util.PrependProxyEnv(cmd), sudo)
	if !r.isSuccess() {
		return "", xerrors.Errorf("Failed to lsof: %s", r)
	}
	return r.Stdout, nil
}

func (l *base) parseLsOf(stdout string) map[string][]string {
	portPids := map[string][]string{}
	scanner := bufio.NewScanner(strings.NewReader(stdout))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "LISTEN") {
			continue
		}
		ss := strings.Fields(line)
		if len(ss) < 10 {
			continue
		}
		pid, ipPort := ss[1], ss[8]
		portPids[ipPort] = util.AppendIfMissing(portPids[ipPort], pid)
	}
	return portPids
}

func (l *base) pkgPs(getOwnerPkgs func([]string) ([]string, error)) error {
	stdout, err := l.ps()
	if err != nil {
		return xerrors.Errorf("Failed to pkgPs: %w", err)
	}
	pidNames := l.parsePs(stdout)
	pidLoadedFiles := map[string][]string{}
	for pid := range pidNames {
		stdout := ""
		stdout, err = l.lsProcExe(pid)
		if err != nil {
			l.log.Debugf("Failed to exec ls -l /proc/%s/exe err: %+v", pid, err)
			continue
		}
		s, err := l.parseLsProcExe(stdout)
		if err != nil {
			l.log.Debugf("Failed to parse /proc/%s/exe: %+v", pid, err)
			continue
		}
		pidLoadedFiles[pid] = append(pidLoadedFiles[pid], s)

		stdout, err = l.grepProcMap(pid)
		if err != nil {
			l.log.Debugf("Failed to exec /proc/%s/maps: %+v", pid, err)
			continue
		}
		ss := l.parseGrepProcMap(stdout)
		pidLoadedFiles[pid] = append(pidLoadedFiles[pid], ss...)
	}

	pidListenPorts := map[string][]models.PortStat{}
	stdout, err = l.lsOfListen()
	if err != nil {
		// warning only, continue scanning
		l.log.Warnf("Failed to lsof: %+v", err)
	}
	portPids := l.parseLsOf(stdout)
	for ipPort, pids := range portPids {
		for _, pid := range pids {
			portStat, err := models.NewPortStat(ipPort)
			if err != nil {
				l.log.Warnf("Failed to parse ip:port: %s, err: %+v", ipPort, err)
				continue
			}
			pidListenPorts[pid] = append(pidListenPorts[pid], *portStat)
		}
	}

	for pid, loadedFiles := range pidLoadedFiles {
		pkgNames, err := getOwnerPkgs(loadedFiles)
		if err != nil {
			l.log.Warnf("Failed to get owner pkgs of: %s", loadedFiles)
			continue
		}
		uniq := map[string]struct{}{}
		for _, name := range pkgNames {
			uniq[name] = struct{}{}
		}

		procName := ""
		if _, ok := pidNames[pid]; ok {
			procName = pidNames[pid]
		}
		proc := models.AffectedProcess{
			PID:             pid,
			Name:            procName,
			ListenPortStats: pidListenPorts[pid],
		}

		for name := range uniq {
			p, ok := l.Packages[name]
			if !ok {
				l.log.Warnf("Failed to find a running pkg: %s", name)
				continue
			}
			p.AffectedProcs = append(p.AffectedProcs, proc)
			l.Packages[p.Name] = p
		}
	}
	return nil
}
