package config

import (
	"fmt"
	"maps"
	"net"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/c-robinson/iplib"
	"github.com/knqyf263/go-cpe/naming"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
)

// TOMLLoader loads config
type TOMLLoader struct {
}

// Load load the configuration TOML file specified by path arg.
func (c TOMLLoader) Load(pathToToml string) error {
	// util.Log.Infof("Loading config: %s", pathToToml)
	if _, err := toml.DecodeFile(pathToToml, &ConfV1); err != nil {
		return err
	}
	if ConfV1.Version != "v2" && runtime.GOOS == "windows" {
		logging.Log.Infof("An outdated version of config.toml was detected. Converting to newer version...")
		if err := convertToLatestConfig(pathToToml); err != nil {
			return xerrors.Errorf("Failed to convert to latest config. err: %w", err)
		}
	} else if _, err := toml.DecodeFile(pathToToml, &Conf); err != nil {
		return err
	}

	for _, cnf := range []VulnDictInterface{
		&Conf.CveDict,
		&Conf.OvalDict,
		&Conf.Gost,
		&Conf.Exploit,
		&Conf.Metasploit,
		&Conf.KEVuln,
		&Conf.Cti,
	} {
		cnf.Init()
	}

	index := 0
	servers := map[string]ServerInfo{}
	for name, server := range Conf.Servers {
		server.BaseName = name

		if server.Type != constant.ServerTypePseudo && server.Host == "" {
			return xerrors.New("Failed to find hosts. err: server.host is empty")
		}
		serverHosts, err := hosts(server.Host, server.IgnoreIPAddresses)
		if err != nil {
			return xerrors.Errorf("Failed to find hosts. err: %w", err)
		}
		if len(serverHosts) == 0 {
			return xerrors.New("Failed to find hosts. err: zero enumerated hosts")
		}

		if err := setDefaultIfEmpty(&server); err != nil {
			return xerrors.Errorf("Failed to set default value to config. server: %s, err: %w", name, err)
		}

		if err := setScanMode(&server); err != nil {
			return xerrors.Errorf("Failed to set ScanMode: %w", err)
		}

		if err := setScanModules(&server, Conf.Default); err != nil {
			return xerrors.Errorf("Failed to set ScanModule: %w", err)
		}

		if len(server.CpeNames) == 0 {
			server.CpeNames = Conf.Default.CpeNames
		}
		for i, n := range server.CpeNames {
			uri, err := toCpeURI(n)
			if err != nil {
				return xerrors.Errorf("Failed to parse CPENames %s in %s, err: %w", n, name, err)
			}
			server.CpeNames[i] = uri
		}

		for _, cve := range Conf.Default.IgnoreCves {
			found := slices.Contains(server.IgnoreCves, cve)
			if !found {
				server.IgnoreCves = append(server.IgnoreCves, cve)
			}
		}

		for _, pkg := range Conf.Default.IgnorePkgsRegexp {
			found := slices.Contains(server.IgnorePkgsRegexp, pkg)
			if !found {
				server.IgnorePkgsRegexp = append(server.IgnorePkgsRegexp, pkg)
			}
		}
		for _, reg := range server.IgnorePkgsRegexp {
			_, err := regexp.Compile(reg)
			if err != nil {
				return xerrors.Errorf("Failed to parse %s in %s. err: %w", reg, name, err)
			}
		}
		for contName, cont := range server.Containers {
			for _, reg := range cont.IgnorePkgsRegexp {
				_, err := regexp.Compile(reg)
				if err != nil {
					return xerrors.Errorf("Failed to parse %s in %s@%s. err: %w", reg, contName, name, err)
				}
			}
		}

		for ownerRepo, githubSetting := range server.GitHubRepos {
			if ss := strings.Split(ownerRepo, "/"); len(ss) != 2 {
				return xerrors.Errorf("Failed to parse GitHub owner/repo: %s in %s", ownerRepo, name)
			}
			if githubSetting.Token == "" {
				return xerrors.Errorf("GitHub owner/repo: %s in %s token is empty", ownerRepo, name)
			}
		}

		if len(server.Enablerepo) == 0 {
			server.Enablerepo = Conf.Default.Enablerepo
		}
		for _, repo := range server.Enablerepo {
			switch repo {
			case "base", "updates":
				// nop
			default:
				return xerrors.Errorf("For now, enablerepo have to be base or updates: %s", server.Enablerepo)
			}
		}

		if server.PortScan.ScannerBinPath != "" {
			server.PortScan.IsUseExternalScanner = true
		}

		if !isCIDRNotation(server.Host) {
			server.ServerName = name
			servers[server.ServerName] = server
			continue
		}
		for _, host := range serverHosts {
			server.Host = host
			server.ServerName = fmt.Sprintf("%s(%s)", name, host)
			server.LogMsgAnsiColor = Colors[index%len(Colors)]
			index++
			servers[server.ServerName] = server
		}
	}
	Conf.Servers = servers

	return nil
}

func hosts(host string, ignores []string) ([]string, error) {
	hostMap := map[string]struct{}{}
	hosts, err := enumerateHosts(host)
	if err != nil {
		return nil, xerrors.Errorf("Failed to enumarate hosts. err: %w", err)
	}
	for _, host := range hosts {
		hostMap[host] = struct{}{}
	}

	for _, ignore := range ignores {
		hosts, err := enumerateHosts(ignore)
		if err != nil {
			return nil, xerrors.Errorf("Failed to enumarate hosts. err: %w", err)
		}
		if len(hosts) == 1 && net.ParseIP(hosts[0]) == nil {
			return nil, xerrors.Errorf("Failed to ignore hosts. err: a non-IP address has been entered in ignoreIPAddress")
		}
		for _, host := range hosts {
			delete(hostMap, host)
		}
	}

	hosts = []string{}
	for host := range hostMap {
		hosts = append(hosts, host)
	}
	return hosts, nil
}

func enumerateHosts(host string) ([]string, error) {
	if !isCIDRNotation(host) {
		return []string{host}, nil
	}

	ipAddr, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		return nil, xerrors.Errorf("Failed to parse CIDR. err: %w", err)
	}
	maskLen, _ := ipNet.Mask.Size()

	addrs := []string{}
	if net.ParseIP(ipAddr.String()).To4() != nil {
		n := iplib.NewNet4(ipAddr, int(maskLen))
		for _, addr := range n.Enumerate(int(n.Count()), 0) {
			addrs = append(addrs, addr.String())
		}
	} else if net.ParseIP(ipAddr.String()).To16() != nil {
		n := iplib.NewNet6(ipAddr, int(maskLen), 0)
		if !n.Count().IsInt64() {
			return nil, xerrors.Errorf("Failed to enumerate IP address. err: mask bitsize too big")
		}
		for _, addr := range n.Enumerate(int(n.Count().Int64()), 0) {
			addrs = append(addrs, addr.String())
		}
	}
	return addrs, nil
}

func isCIDRNotation(host string) bool {
	ss := strings.Split(host, "/")
	if len(ss) == 1 || net.ParseIP(ss[0]) == nil {
		return false
	}
	return true
}

func setDefaultIfEmpty(server *ServerInfo) error {
	if server.Type != constant.ServerTypePseudo {
		if len(server.JumpServer) == 0 {
			server.JumpServer = Conf.Default.JumpServer
		}

		if server.Port == "" {
			server.Port = Conf.Default.Port
		}

		if server.User == "" {
			server.User = Conf.Default.User
		}

		if server.SSHConfigPath == "" {
			server.SSHConfigPath = Conf.Default.SSHConfigPath
		}

		if server.KeyPath == "" {
			server.KeyPath = Conf.Default.KeyPath
		}
	}

	if len(server.Lockfiles) == 0 {
		server.Lockfiles = Conf.Default.Lockfiles
	}

	if len(server.ContainersIncluded) == 0 {
		server.ContainersIncluded = Conf.Default.ContainersIncluded
	}

	if len(server.ContainersExcluded) == 0 {
		server.ContainersExcluded = Conf.Default.ContainersExcluded
	}

	if server.ContainerType == "" {
		server.ContainerType = Conf.Default.ContainerType
	}

	for contName, cont := range server.Containers {
		cont.IgnoreCves = append(cont.IgnoreCves, Conf.Default.IgnoreCves...)
		server.Containers[contName] = cont
	}

	if server.OwaspDCXMLPath == "" {
		server.OwaspDCXMLPath = Conf.Default.OwaspDCXMLPath
	}

	if server.Memo == "" {
		server.Memo = Conf.Default.Memo
	}

	if server.WordPress == nil {
		server.WordPress = Conf.Default.WordPress
		if server.WordPress == nil {
			server.WordPress = &WordPressConf{}
		}
	}

	if server.PortScan == nil {
		server.PortScan = Conf.Default.PortScan
		if server.PortScan == nil {
			server.PortScan = &PortScanConf{}
		}
	}

	if server.Windows == nil {
		server.Windows = Conf.Default.Windows
		if server.Windows == nil {
			server.Windows = &WindowsConf{}
		}
	}

	if len(server.IgnoredJSONKeys) == 0 {
		server.IgnoredJSONKeys = Conf.Default.IgnoredJSONKeys
	}

	opt := map[string]any{}
	maps.Copy(opt, Conf.Default.Optional)
	maps.Copy(opt, server.Optional)
	server.Optional = opt

	return nil
}

func toCpeURI(cpename string) (string, error) {
	if strings.HasPrefix(cpename, "cpe:2.3:") {
		wfn, err := naming.UnbindFS(cpename)
		if err != nil {
			return "", err
		}
		return naming.BindToURI(wfn), nil
	} else if strings.HasPrefix(cpename, "cpe:/") {
		wfn, err := naming.UnbindURI(cpename)
		if err != nil {
			return "", err
		}
		return naming.BindToURI(wfn), nil
	}
	return "", xerrors.Errorf("Unknown CPE format: %s", cpename)
}
