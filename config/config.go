package config

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/asaskevich/govalidator"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// Version of Vuls
var Version = "`make build` or `make install` will show the version"

// Revision of Git
var Revision string

// Conf has Configuration
var Conf Config

//Config is struct of Configuration
type Config struct {
	Debug      bool   `json:"debug,omitempty"`
	DebugSQL   bool   `json:"debugSQL,omitempty"`
	Lang       string `json:"lang,omitempty"`
	HTTPProxy  string `valid:"url" json:"httpProxy,omitempty"`
	LogDir     string `json:"logDir,omitempty"`
	ResultsDir string `json:"resultsDir,omitempty"`
	Pipe       bool   `json:"pipe,omitempty"`
	Quiet      bool   `json:"quiet,omitempty"`
	NoProgress bool   `json:"noProgress,omitempty"`
	SSHNative  bool   `json:"sshNative,omitempty"`
	Vvv        bool   `json:"vvv,omitempty"`

	Default       ServerInfo            `json:"default,omitempty"`
	Servers       map[string]ServerInfo `json:"servers,omitempty"`
	CvssScoreOver float64               `json:"cvssScoreOver,omitempty"`

	IgnoreUnscoredCves    bool `json:"ignoreUnscoredCves,omitempty"`
	IgnoreUnfixed         bool `json:"ignoreUnfixed,omitempty"`
	IgnoreGitHubDismissed bool `json:"ignore_git_hub_dismissed,omitempty"`

	CacheDBPath     string `json:"cacheDBPath,omitempty"`
	TrivyCacheDBDir string `json:"trivyCacheDBDir,omitempty"`

	CveDict    GoCveDictConf  `json:"cveDict,omitempty"`
	OvalDict   GovalDictConf  `json:"ovalDict,omitempty"`
	Gost       GostConf       `json:"gost,omitempty"`
	Exploit    ExploitConf    `json:"exploit,omitempty"`
	Metasploit MetasploitConf `json:"metasploit,omitempty"`

	Slack    SlackConf    `json:"-"`
	EMail    SMTPConf     `json:"-"`
	HTTP     HTTPConf     `json:"-"`
	Syslog   SyslogConf   `json:"-"`
	AWS      AWSConf      `json:"-"`
	Azure    AzureConf    `json:"-"`
	ChatWork ChatWorkConf `json:"-"`
	Telegram TelegramConf `json:"-"`

	WpScan WpScanConf `json:"WpScan,omitempty"`

	Saas      SaasConf `json:"-"`
	DetectIPS bool     `json:"detectIps,omitempty"`

	RefreshCve        bool `json:"refreshCve,omitempty"`
	ToSlack           bool `json:"toSlack,omitempty"`
	ToChatWork        bool `json:"toChatWork,omitempty"`
	ToTelegram        bool `json:"ToTelegram,omitempty"`
	ToEmail           bool `json:"toEmail,omitempty"`
	ToSyslog          bool `json:"toSyslog,omitempty"`
	ToLocalFile       bool `json:"toLocalFile,omitempty"`
	ToS3              bool `json:"toS3,omitempty"`
	ToAzureBlob       bool `json:"toAzureBlob,omitempty"`
	ToHTTP            bool `json:"toHTTP,omitempty"`
	FormatJSON        bool `json:"formatJSON,omitempty"`
	FormatOneEMail    bool `json:"formatOneEMail,omitempty"`
	FormatOneLineText bool `json:"formatOneLineText,omitempty"`
	FormatList        bool `json:"formatList,omitempty"`
	FormatFullText    bool `json:"formatFullText,omitempty"`
	FormatCsvList     bool `json:"formatCsvList,omitempty"`
	GZIP              bool `json:"gzip,omitempty"`
	Diff              bool `json:"diff,omitempty"`
}

// ValidateOnConfigtest validates
func (c Config) ValidateOnConfigtest() bool {
	errs := c.checkSSHKeyExist()

	if runtime.GOOS == "windows" && !c.SSHNative {
		errs = append(errs, xerrors.New("-ssh-native-insecure is needed on windows"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

// ValidateOnScan validates configuration
func (c Config) ValidateOnScan() bool {
	errs := c.checkSSHKeyExist()

	if runtime.GOOS == "windows" && !c.SSHNative {
		errs = append(errs, xerrors.New("-ssh-native-insecure is needed on windows"))
	}

	if len(c.ResultsDir) != 0 {
		if ok, _ := govalidator.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, xerrors.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if len(c.CacheDBPath) != 0 {
		if ok, _ := govalidator.IsFilePath(c.CacheDBPath); !ok {
			errs = append(errs, xerrors.Errorf(
				"Cache DB path must be a *Absolute* file path. -cache-dbpath: %s",
				c.CacheDBPath))
		}
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

func (c Config) checkSSHKeyExist() (errs []error) {
	for serverName, v := range c.Servers {
		if v.Type == ServerTypePseudo {
			continue
		}
		if v.KeyPath != "" {
			if _, err := os.Stat(v.KeyPath); err != nil {
				errs = append(errs, xerrors.Errorf(
					"%s is invalid. keypath: %s not exists", serverName, v.KeyPath))
			}
		}
	}
	return errs
}

// ValidateOnReportDB validates configuration
func (c Config) ValidateOnReportDB() bool {
	errs := []error{}

	if err := validateDB("cvedb", c.CveDict.Type, c.CveDict.SQLite3Path, c.CveDict.URL); err != nil {
		errs = append(errs, err)
	}

	if err := validateDB("ovaldb", c.OvalDict.Type, c.OvalDict.SQLite3Path, c.OvalDict.URL); err != nil {
		errs = append(errs, err)
	}

	if err := validateDB("gostdb", c.Gost.Type, c.Gost.SQLite3Path, c.Gost.URL); err != nil {
		errs = append(errs, err)
	}

	if err := validateDB("exploitdb", c.Exploit.Type, c.Exploit.SQLite3Path, c.Exploit.URL); err != nil {
		errs = append(errs, err)
	}

	if err := validateDB("msfdb", c.Metasploit.Type, c.Metasploit.SQLite3Path, c.Metasploit.URL); err != nil {
		errs = append(errs, err)
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

// ValidateOnReport validates configuration
func (c Config) ValidateOnReport() bool {
	errs := []error{}

	if len(c.ResultsDir) != 0 {
		if ok, _ := govalidator.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, xerrors.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	if mailerrs := c.EMail.Validate(); 0 < len(mailerrs) {
		errs = append(errs, mailerrs...)
	}

	if slackerrs := c.Slack.Validate(); 0 < len(slackerrs) {
		errs = append(errs, slackerrs...)
	}

	if chatworkerrs := c.ChatWork.Validate(); 0 < len(chatworkerrs) {
		errs = append(errs, chatworkerrs...)
	}

	if telegramerrs := c.Telegram.Validate(); 0 < len(telegramerrs) {
		errs = append(errs, telegramerrs...)
	}

	if syslogerrs := c.Syslog.Validate(); 0 < len(syslogerrs) {
		errs = append(errs, syslogerrs...)
	}

	if httperrs := c.HTTP.Validate(); 0 < len(httperrs) {
		errs = append(errs, httperrs...)
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

// ValidateOnTui validates configuration
func (c Config) ValidateOnTui() bool {
	errs := []error{}

	if len(c.ResultsDir) != 0 {
		if ok, _ := govalidator.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, xerrors.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if err := validateDB("cvedb", c.CveDict.Type, c.CveDict.SQLite3Path, c.CveDict.URL); err != nil {
		errs = append(errs, err)
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

// ValidateOnSaaS validates configuration
func (c Config) ValidateOnSaaS() bool {
	saaserrs := c.Saas.Validate()
	for _, err := range saaserrs {
		log.Error("Failed to validate SaaS conf: %+w", err)
	}
	return len(saaserrs) == 0
}

// validateDB validates configuration
func validateDB(dictionaryDBName, dbType, dbPath, dbURL string) error {
	log.Infof("-%s-type: %s, -%s-url: %s, -%s-path: %s",
		dictionaryDBName, dbType, dictionaryDBName, dbURL, dictionaryDBName, dbPath)

	switch dbType {
	case "sqlite3":
		if dbURL != "" {
			return xerrors.Errorf("To use SQLite3, specify -%s-type=sqlite3 and -%s-path. To use as http server mode, specify -%s-type=http and -%s-url",
				dictionaryDBName, dictionaryDBName, dictionaryDBName, dictionaryDBName)
		}
		if ok, _ := govalidator.IsFilePath(dbPath); !ok {
			return xerrors.Errorf("SQLite3 path must be a *Absolute* file path. -%s-path: %s",
				dictionaryDBName, dbPath)
		}
	case "mysql":
		if dbURL == "" {
			return xerrors.Errorf(`MySQL connection string is needed. -%s-url="user:pass@tcp(localhost:3306)/dbname"`,
				dictionaryDBName)
		}
	case "postgres":
		if dbURL == "" {
			return xerrors.Errorf(`PostgreSQL connection string is needed. -%s-url="host=myhost user=user dbname=dbname sslmode=disable password=password"`,
				dictionaryDBName)
		}
	case "redis":
		if dbURL == "" {
			return xerrors.Errorf(`Redis connection string is needed. -%s-url="redis://localhost/0"`,
				dictionaryDBName)
		}
	case "http":
		if dbURL == "" {
			return xerrors.Errorf(`URL is needed. -%s-url="http://localhost:1323"`,
				dictionaryDBName)
		}
	default:
		return xerrors.Errorf("%s type must be either 'sqlite3', 'mysql', 'postgres', 'redis' or 'http'.  -%s-type: %s",
			dictionaryDBName, dictionaryDBName, dbType)
	}
	return nil
}

// AWSConf is aws config
type AWSConf struct {
	// AWS profile to use
	Profile string `json:"profile"`

	// AWS region to use
	Region string `json:"region"`

	// S3 bucket name
	S3Bucket string `json:"s3Bucket"`

	// /bucket/path/to/results
	S3ResultsDir string `json:"s3ResultsDir"`

	// The Server-side encryption algorithm used when storing the reports in S3 (e.g., AES256, aws:kms).
	S3ServerSideEncryption string `json:"s3ServerSideEncryption"`
}

// AzureConf is azure config
type AzureConf struct {
	// Azure account name to use. AZURE_STORAGE_ACCOUNT environment variable is used if not specified
	AccountName string `json:"accountName"`

	// Azure account key to use. AZURE_STORAGE_ACCESS_KEY environment variable is used if not specified
	AccountKey string `json:"-"`

	// Azure storage container name
	ContainerName string `json:"containerName"`
}

// WpScanConf is wpscan.com config
type WpScanConf struct {
	Token          string `toml:"Token,omitempty" json:"-"`
	DetectInactive bool   `toml:"detectInactive,omitempty" json:"detectInactive,omitempty"`
}

// ServerInfo has SSH Info, additional CPE packages to scan.
type ServerInfo struct {
	ServerName         string                      `toml:"-" json:"serverName,omitempty"`
	User               string                      `toml:"user,omitempty" json:"user,omitempty"`
	Host               string                      `toml:"host,omitempty" json:"host,omitempty"`
	JumpServer         []string                    `toml:"jumpServer,omitempty" json:"jumpServer,omitempty"`
	Port               string                      `toml:"port,omitempty" json:"port,omitempty"`
	SSHConfigPath      string                      `toml:"sshConfigPath,omitempty" json:"sshConfigPath,omitempty"`
	KeyPath            string                      `toml:"keyPath,omitempty" json:"keyPath,omitempty"`
	KeyPassword        string                      `json:"-" toml:"-"`
	CpeNames           []string                    `toml:"cpeNames,omitempty" json:"cpeNames,omitempty"`
	ScanMode           []string                    `toml:"scanMode,omitempty" json:"scanMode,omitempty"`
	ScanModules        []string                    `toml:"scanModules,omitempty" json:"scanModules,omitempty"`
	OwaspDCXMLPath     string                      `toml:"owaspDCXMLPath,omitempty" json:"owaspDCXMLPath,omitempty"`
	ContainersOnly     bool                        `toml:"containersOnly,omitempty" json:"containersOnly,omitempty"`
	ContainersIncluded []string                    `toml:"containersIncluded,omitempty" json:"containersIncluded,omitempty"`
	ContainersExcluded []string                    `toml:"containersExcluded,omitempty" json:"containersExcluded,omitempty"`
	ContainerType      string                      `toml:"containerType,omitempty" json:"containerType,omitempty"`
	Containers         map[string]ContainerSetting `toml:"containers,omitempty" json:"containers,omitempty"`
	IgnoreCves         []string                    `toml:"ignoreCves,omitempty" json:"ignoreCves,omitempty"`
	IgnorePkgsRegexp   []string                    `toml:"ignorePkgsRegexp,omitempty" json:"ignorePkgsRegexp,omitempty"`
	GitHubRepos        map[string]GitHubConf       `toml:"githubs" json:"githubs,omitempty"` // key: owner/repo
	UUIDs              map[string]string           `toml:"uuids,omitempty" json:"uuids,omitempty"`
	Memo               string                      `toml:"memo,omitempty" json:"memo,omitempty"`
	Enablerepo         []string                    `toml:"enablerepo,omitempty" json:"enablerepo,omitempty"` // For CentOS, RHEL, Amazon
	Optional           map[string]interface{}      `toml:"optional,omitempty" json:"optional,omitempty"`     // Optional key-value set that will be outputted to JSON
	Lockfiles          []string                    `toml:"lockfiles,omitempty" json:"lockfiles,omitempty"`   // ie) path/to/package-lock.json
	FindLock           bool                        `toml:"findLock,omitempty" json:"findLock,omitempty"`
	Type               string                      `toml:"type,omitempty" json:"type,omitempty"` // "pseudo" or ""
	IgnoredJSONKeys    []string                    `toml:"ignoredJSONKeys,omitempty" json:"ignoredJSONKeys,omitempty"`
	IPv4Addrs          []string                    `toml:"-" json:"ipv4Addrs,omitempty"`
	IPv6Addrs          []string                    `toml:"-" json:"ipv6Addrs,omitempty"`
	IPSIdentifiers     map[IPS]string              `toml:"-" json:"ipsIdentifiers,omitempty"`
	WordPress          *WordPressConf              `toml:"wordpress,omitempty" json:"wordpress,omitempty"`

	// internal use
	LogMsgAnsiColor string     `toml:"-" json:"-"` // DebugLog Color
	Container       Container  `toml:"-" json:"-"`
	Distro          Distro     `toml:"-" json:"-"`
	Mode            ScanMode   `toml:"-" json:"-"`
	Module          ScanModule `toml:"-" json:"-"`
}

// ContainerSetting is used for loading container setting in config.toml
type ContainerSetting struct {
	Cpes             []string `json:"cpes,omitempty"`
	OwaspDCXMLPath   string   `json:"owaspDCXMLPath,omitempty"`
	IgnorePkgsRegexp []string `json:"ignorePkgsRegexp,omitempty"`
	IgnoreCves       []string `json:"ignoreCves,omitempty"`
}

// WordPressConf used for WordPress Scanning
type WordPressConf struct {
	OSUser  string `toml:"osUser,omitempty" json:"osUser,omitempty"`
	DocRoot string `toml:"docRoot,omitempty" json:"docRoot,omitempty"`
	CmdPath string `toml:"cmdPath,omitempty" json:"cmdPath,omitempty"`
}

// IsZero return  whether this struct is not specified in config.toml
func (cnf WordPressConf) IsZero() bool {
	return cnf.OSUser == "" && cnf.DocRoot == "" && cnf.CmdPath == ""
}

// GitHubConf is used for GitHub Security Alerts
type GitHubConf struct {
	Token string `json:"-"`
}

// GetServerName returns ServerName if this serverInfo is about host.
// If this serverInfo is about a container, returns containerID@ServerName
func (s ServerInfo) GetServerName() string {
	if len(s.Container.ContainerID) == 0 {
		return s.ServerName
	}
	return fmt.Sprintf("%s@%s", s.Container.Name, s.ServerName)
}

// Distro has distribution info
type Distro struct {
	Family  string
	Release string
}

func (l Distro) String() string {
	return fmt.Sprintf("%s %s", l.Family, l.Release)
}

// MajorVersion returns Major version
func (l Distro) MajorVersion() (int, error) {
	if l.Family == Amazon {
		if isAmazonLinux1(l.Release) {
			return 1, nil
		}
		return 2, nil
	}
	if 0 < len(l.Release) {
		return strconv.Atoi(strings.Split(l.Release, ".")[0])
	}
	return 0, xerrors.New("Release is empty")
}

// IsContainer returns whether this ServerInfo is about container
func (s ServerInfo) IsContainer() bool {
	return 0 < len(s.Container.ContainerID)
}

// SetContainer set container
func (s *ServerInfo) SetContainer(d Container) {
	s.Container = d
}

// Container has Container information.
type Container struct {
	ContainerID string
	Name        string
	Image       string
}

// VulnSrcConf is an interface of vulnsrc
type VulnSrcConf interface {
	CheckHTTPHealth() error
}
