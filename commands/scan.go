package commands

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/scan"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/k0kubun/pp"
)

// ScanCmd is Subcommand of host discovery mode
type ScanCmd struct {
	configPath     string
	askKeyPassword bool
	timeoutSec     int
	scanTimeoutSec int
}

// Name return subcommand name
func (*ScanCmd) Name() string { return "scan" }

// Synopsis return synopsis
func (*ScanCmd) Synopsis() string { return "Scan vulnerabilities" }

// Usage return usage
func (*ScanCmd) Usage() string {
	return `scan:
	scan
		[-config=/path/to/config.toml]
		[-results-dir=/path/to/results]
		[-log-dir=/path/to/log]
		[-cachedb-path=/path/to/cache.db]
		[-ssh-native-insecure]
		[-ssh-config]
		[-containers-only]
		[-images-only]
		[-libs-only]
		[-wordpress-only]
		[-skip-broken]
		[-http-proxy=http://192.168.0.1:8080]
		[-ask-key-password]
		[-timeout=300]
		[-timeout-scan=7200]
		[-debug]
		[-pipe]
		[-vvv]
		[-ips]


		[SERVER]...
`
}

// SetFlags set flag
func (p *ScanCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&c.Conf.Debug, "debug", false, "debug mode")

	wd, _ := os.Getwd()
	defaultConfPath := filepath.Join(wd, "config.toml")
	f.StringVar(&p.configPath, "config", defaultConfPath, "/path/to/toml")

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&c.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	defaultLogDir := util.GetDefaultLogDir()
	f.StringVar(&c.Conf.LogDir, "log-dir", defaultLogDir, "/path/to/log")

	defaultCacheDBPath := filepath.Join(wd, "cache.db")
	f.StringVar(&c.Conf.CacheDBPath, "cachedb-path", defaultCacheDBPath,
		"/path/to/cache.db (local cache of changelog for Ubuntu/Debian)")

	f.BoolVar(&c.Conf.SSHNative, "ssh-native-insecure", false,
		"Use Native Go implementation of SSH. Default: Use the external command")

	f.BoolVar(&c.Conf.SSHConfig, "ssh-config", false,
		"Use SSH options specified in ssh_config preferentially")

	f.BoolVar(&c.Conf.ContainersOnly, "containers-only", false,
		"Scan running containers only. Default: Scan both of hosts and running containers")

	f.BoolVar(&c.Conf.ImagesOnly, "images-only", false,
		"Scan container images only. Default: Scan both of hosts and images")

	f.BoolVar(&c.Conf.LibsOnly, "libs-only", false,
		"Scan libraries (lock files) specified in config.toml only.")

	f.BoolVar(&c.Conf.WordPressOnly, "wordpress-only", false,
		"Scan WordPress only.")

	f.BoolVar(&c.Conf.SkipBroken, "skip-broken", false,
		"[For CentOS] yum update changelog with --skip-broken option")

	f.StringVar(&c.Conf.HTTPProxy, "http-proxy", "",
		"http://proxy-url:port (default: empty)")

	f.BoolVar(&p.askKeyPassword, "ask-key-password", false,
		"Ask ssh privatekey password before scanning",
	)

	f.BoolVar(&c.Conf.Pipe, "pipe", false, "Use stdin via PIPE")

	f.BoolVar(&c.Conf.DetectIPS, "ips", false, "retrieve IPS information")
	f.BoolVar(&c.Conf.Vvv, "vvv", false, "ssh -vvv")

	f.IntVar(&p.timeoutSec, "timeout", 5*60,
		"Number of seconds for processing other than scan",
	)

	f.IntVar(&p.scanTimeoutSec, "timeout-scan", 120*60,
		"Number of seconds for scanning vulnerabilities for all servers",
	)
}

// Execute execute
func (p *ScanCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	// Setup Logger
	util.Log = util.NewCustomLogger(c.ServerInfo{})

	if err := mkdirDotVuls(); err != nil {
		util.Log.Errorf("Failed to create .vuls. err: %+v", err)
		return subcommands.ExitUsageError
	}

	var keyPass string
	var err error
	if p.askKeyPassword {
		prompt := "SSH key password: "
		if keyPass, err = getPasswd(prompt); err != nil {
			util.Log.Error(err)
			return subcommands.ExitFailure
		}
	}

	err = c.Load(p.configPath, keyPass)
	if err != nil {
		msg := []string{
			fmt.Sprintf("Error loading %s", p.configPath),
			"If you update Vuls and get this error, there may be incompatible changes in config.toml",
			"Please check config.toml template : https://vuls.io/docs/en/usage-settings.html",
		}
		util.Log.Errorf("%s\n%+v", strings.Join(msg, "\n"), err)
		return subcommands.ExitUsageError
	}

	util.Log.Info("Start scanning")
	util.Log.Infof("config: %s", p.configPath)

	var servernames []string
	if 0 < len(f.Args()) {
		servernames = f.Args()
	} else if c.Conf.Pipe {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			util.Log.Errorf("Failed to read stdin. err: %+v", err)
			return subcommands.ExitFailure
		}
		fields := strings.Fields(string(bytes))
		if 0 < len(fields) {
			servernames = fields
		}
	}

	target := make(map[string]c.ServerInfo)
	for _, arg := range servernames {
		found := false
		for servername, info := range c.Conf.Servers {
			if servername == arg {
				target[servername] = info
				found = true
				break
			}
		}
		if !found {
			util.Log.Errorf("%s is not in config", arg)
			return subcommands.ExitUsageError
		}
	}
	if 0 < len(servernames) {
		c.Conf.Servers = target
	}
	util.Log.Debugf("%s", pp.Sprintf("%v", target))

	util.Log.Info("Validating config...")
	if !c.Conf.ValidateOnScan() {
		return subcommands.ExitUsageError
	}

	util.Log.Info("Detecting Server/Container OS... ")
	if err := scan.InitServers(p.timeoutSec); err != nil {
		util.Log.Errorf("Failed to init servers: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Checking Scan Modes... ")
	if err := scan.CheckScanModes(); err != nil {
		util.Log.Errorf("Fix config.toml. err: %+v", err)
		return subcommands.ExitFailure
	}

	util.Log.Info("Detecting Platforms... ")
	scan.DetectPlatforms(p.timeoutSec)
	util.Log.Info("Detecting IPS identifiers... ")
	scan.DetectIPSs(p.timeoutSec)

	util.Log.Info("Scanning vulnerabilities... ")
	if err := scan.Scan(p.scanTimeoutSec); err != nil {
		util.Log.Errorf("Failed to scan. err: %+v", err)
		return subcommands.ExitFailure
	}
	fmt.Printf("\n\n\n")
	fmt.Println("To view the detail, vuls tui is useful.")
	fmt.Println("To send a report, run vuls report -h.")

	return subcommands.ExitSuccess
}
