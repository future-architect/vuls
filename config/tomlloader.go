package config

import (
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/constant"
	"github.com/knqyf263/go-cpe/naming"
	"golang.org/x/xerrors"
)

// TOMLLoader loads config
type TOMLLoader struct {
}

// Load load the configuration TOML file specified by path arg.
func (c TOMLLoader) Load(pathToToml, keyPass string) error {
	// util.Log.Infof("Loading config: %s", pathToToml)
	if _, err := toml.DecodeFile(pathToToml, &Conf); err != nil {
		return err
	}

	for _, cnf := range []VulnDictInterface{
		&Conf.CveDict,
		&Conf.OvalDict,
		&Conf.Gost,
		&Conf.Exploit,
		&Conf.Metasploit,
	} {
		cnf.Init()
	}

	index := 0
	for name, server := range Conf.Servers {
		server.ServerName = name
		if err := setDefaultIfEmpty(&server, Conf.Default); err != nil {
			return xerrors.Errorf("Failed to set default value to config. server: %s, err: %w", name, err)
		}

		if err := setScanMode(&server, Conf.Default); err != nil {
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
			found := false
			for _, c := range server.IgnoreCves {
				if cve == c {
					found = true
					break
				}
			}
			if !found {
				server.IgnoreCves = append(server.IgnoreCves, cve)
			}
		}

		for _, pkg := range Conf.Default.IgnorePkgsRegexp {
			found := false
			for _, p := range server.IgnorePkgsRegexp {
				if pkg == p {
					found = true
					break
				}
			}
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
					return xerrors.Errorf("Failed to parse %s in %s@%s. err: %w",
						reg, contName, name, err)
				}
			}
		}

		for ownerRepo, githubSetting := range server.GitHubRepos {
			if ss := strings.Split(ownerRepo, "/"); len(ss) != 2 {
				return xerrors.Errorf("Failed to parse GitHub owner/repo: %s in %s",
					ownerRepo, name)
			}
			if githubSetting.Token == "" {
				return xerrors.Errorf("GitHub owner/repo: %s in %s token is empty",
					ownerRepo, name)
			}
		}

		if len(server.Enablerepo) == 0 {
			server.Enablerepo = Conf.Default.Enablerepo
		}
		if len(server.Enablerepo) != 0 {
			for _, repo := range server.Enablerepo {
				switch repo {
				case "base", "updates":
					// nop
				default:
					return xerrors.Errorf(
						"For now, enablerepo have to be base or updates: %s",
						server.Enablerepo)
				}
			}
		}

		if server.PortScan.ScannerBinPath != "" {
			server.PortScan.IsUseExternalScanner = true
		}

		server.LogMsgAnsiColor = Colors[index%len(Colors)]
		index++

		Conf.Servers[name] = server
	}
	return nil
}

func setDefaultIfEmpty(server *ServerInfo, d ServerInfo) error {
	if server.Type != constant.ServerTypePseudo {
		if len(server.Host) == 0 {
			return xerrors.Errorf("server.host is empty")
		}

		if len(server.JumpServer) == 0 {
			server.JumpServer = Conf.Default.JumpServer
		}

		if server.Port == "" {
			if Conf.Default.Port != "" {
				server.Port = Conf.Default.Port
			} else {
				server.Port = "22"
			}
		}

		if server.User == "" {
			server.User = Conf.Default.User
			if server.User == "" && server.Port != "local" {
				return xerrors.Errorf("server.user is empty")
			}
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

	if len(server.IgnoredJSONKeys) == 0 {
		server.IgnoredJSONKeys = Conf.Default.IgnoredJSONKeys
	}

	opt := map[string]interface{}{}
	for k, v := range Conf.Default.Optional {
		opt[k] = v
	}
	for k, v := range server.Optional {
		opt[k] = v
	}
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
