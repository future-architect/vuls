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

package config

import (
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"runtime"
	"strconv"
	"strings"

	valid "github.com/asaskevich/govalidator"
	log "github.com/sirupsen/logrus"
)

// Version of Vuls
var Version = "0.5.0"

// Revision of Git
var Revision string

// Conf has Configuration
var Conf Config

const (
	// RedHat is
	RedHat = "redhat"

	// Debian is
	Debian = "debian"

	// Ubuntu is
	Ubuntu = "ubuntu"

	// CentOS is
	CentOS = "centos"

	// Fedora is
	Fedora = "fedora"

	// Amazon is
	Amazon = "amazon"

	// Oracle is
	Oracle = "oracle"

	// FreeBSD is
	FreeBSD = "freebsd"

	// Raspbian is
	Raspbian = "raspbian"

	// Windows is
	Windows = "windows"

	// OpenSUSE is
	OpenSUSE = "opensuse"

	// OpenSUSELeap is
	OpenSUSELeap = "opensuse.leap"

	// SUSEEnterpriseServer is
	SUSEEnterpriseServer = "suse.linux.enterprise.server"

	// SUSEEnterpriseDesktop is
	SUSEEnterpriseDesktop = "suse.linux.enterprise.desktop"

	// SUSEOpenstackCloud is
	SUSEOpenstackCloud = "suse.openstack.cloud"

	// Alpine is
	Alpine = "alpine"
)

const (
	// ServerTypePseudo is used for ServerInfo.Type
	ServerTypePseudo = "pseudo"
)

//Config is struct of Configuration
type Config struct {
	Debug    bool
	DebugSQL bool
	Lang     string

	EMail    SMTPConf
	Slack    SlackConf
	Stride   StrideConf
	HipChat  HipChatConf
	ChatWork ChatWorkConf
	Syslog   SyslogConf
	Default  ServerInfo
	Servers  map[string]ServerInfo

	CvssScoreOver      float64
	IgnoreUnscoredCves bool
	IgnoreUnfixed      bool

	SSHNative bool
	SSHConfig bool

	ContainersOnly bool
	SkipBroken     bool

	HTTPProxy  string `valid:"url"`
	LogDir     string
	ResultsDir string

	CveDBType string
	CveDBPath string
	CveDBURL  string

	OvalDBType string
	OvalDBPath string
	OvalDBURL  string

	CacheDBPath string

	RefreshCve bool

	ToSlack     bool
	ToStride    bool
	ToHipChat   bool
	ToChatWork  bool
	ToEmail     bool
	ToSyslog    bool
	ToLocalFile bool
	ToS3        bool
	ToAzureBlob bool
	ToHTTP      string

	FormatXML         bool
	FormatJSON        bool
	FormatOneEMail    bool
	FormatOneLineText bool
	FormatShortText   bool
	FormatFullText    bool

	GZIP bool

	AwsProfile             string
	AwsRegion              string
	S3Bucket               string
	S3ResultsDir           string
	S3ServerSideEncryption string

	AzureAccount   string
	AzureKey       string `json:"-"`
	AzureContainer string

	Pipe bool
	Vvv  bool
	Diff bool
	UUID bool
}

// ValidateOnConfigtest validates
func (c Config) ValidateOnConfigtest() bool {
	errs := []error{}

	if runtime.GOOS == "windows" && !c.SSHNative {
		errs = append(errs, fmt.Errorf("-ssh-native-insecure is needed on windows"))
	}

	_, err := valid.ValidateStruct(c)
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
	errs := []error{}

	if len(c.ResultsDir) != 0 {
		if ok, _ := valid.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, fmt.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if runtime.GOOS == "windows" && !c.SSHNative {
		errs = append(errs, fmt.Errorf("-ssh-native-insecure is needed on windows"))
	}

	if len(c.ResultsDir) != 0 {
		if ok, _ := valid.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, fmt.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if len(c.CacheDBPath) != 0 {
		if ok, _ := valid.IsFilePath(c.CacheDBPath); !ok {
			errs = append(errs, fmt.Errorf(
				"Cache DB path must be a *Absolute* file path. -cache-dbpath: %s", c.CacheDBPath))
		}
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
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
		if ok, _ := valid.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, fmt.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if err := validateDB("cvedb", c.CveDBType, c.CveDBPath, c.CveDBURL); err != nil {
		errs = append(errs, err)
	}
	if c.CveDBType == "sqlite3" {
		if _, err := os.Stat(c.CveDBPath); os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("SQLite3 DB path (%s) is not exist: %s", "cvedb", c.CveDBPath))
		}
	}

	if err := validateDB("ovaldb", c.OvalDBType, c.OvalDBPath, c.OvalDBURL); err != nil {
		errs = append(errs, err)
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	if mailerrs := c.EMail.Validate(); 0 < len(mailerrs) {
		errs = append(errs, mailerrs...)
	}

	if slackerrs := c.Slack.Validate(); 0 < len(slackerrs) {
		errs = append(errs, slackerrs...)
	}

	if hipchaterrs := c.HipChat.Validate(); 0 < len(hipchaterrs) {
		errs = append(errs, hipchaterrs...)
	}

	if chatworkerrs := c.ChatWork.Validate(); 0 < len(chatworkerrs) {
		errs = append(errs, chatworkerrs...)
	}

	if strideerrs := c.Stride.Validate(); 0 < len(strideerrs) {
		errs = append(errs, strideerrs...)
	}

	if syslogerrs := c.Syslog.Validate(); 0 < len(syslogerrs) {
		errs = append(errs, syslogerrs...)
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
		if ok, _ := valid.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, fmt.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if err := validateDB("cvedb", c.CveDBType, c.CveDBPath, c.CveDBURL); err != nil {
		errs = append(errs, err)
	}
	if c.CveDBType == "sqlite3" {
		if _, err := os.Stat(c.CveDBPath); os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("SQLite3 DB path (%s) is not exist: %s", "cvedb", c.CveDBPath))
		}
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

// validateDB validates configuration
//  dictionaryDB name is 'cvedb' or 'ovaldb'
func validateDB(dictionaryDBName, dbType, dbPath, dbURL string) error {
	switch dbType {
	case "sqlite3":
		if ok, _ := valid.IsFilePath(dbPath); !ok {
			return fmt.Errorf(
				"SQLite3 DB path (%s) must be a *Absolute* file path. -%s-path: %s",
				dictionaryDBName,
				dictionaryDBName,
				dbPath)
		}
	case "mysql":
		if dbURL == "" {
			return fmt.Errorf(
				`MySQL connection string is needed. -%s-url="user:pass@tcp(localhost:3306)/dbname"`,
				dictionaryDBName)
		}
	case "postgres":
		if dbURL == "" {
			return fmt.Errorf(
				`PostgreSQL connection string is needed. -%s-url="host=myhost user=user dbname=dbname sslmode=disable password=password"`,
				dictionaryDBName)
		}
	case "redis":
		if dbURL == "" {
			return fmt.Errorf(
				`Redis connection string is needed. -%s-url="redis://localhost/0"`,
				dictionaryDBName)
		}
	default:
		return fmt.Errorf(
			"%s type must be either 'sqlite3', 'mysql', 'postgres' or 'redis'.  -%s-type: %s",
			dictionaryDBName,
			dictionaryDBName,
			dbType)
	}
	return nil
}

// SMTPConf is smtp config
type SMTPConf struct {
	SMTPAddr      string   `toml:"smtpAddr,omitempty"`
	SMTPPort      string   `toml:"smtpPort,omitempty" valid:"port"`
	User          string   `toml:"user,omitempty"`
	Password      string   `toml:"password,omitempty" json:"-"`
	From          string   `toml:"from,omitempty"`
	To            []string `toml:"to,omitempty" json:",omitempty"`
	Cc            []string `toml:"cc,omitempty" json:",omitempty"`
	SubjectPrefix string   `toml:"subjectPrefix,omitempty"`
}

func checkEmails(emails []string) (errs []error) {
	for _, addr := range emails {
		if len(addr) == 0 {
			return
		}
		if ok := valid.IsEmail(addr); !ok {
			errs = append(errs, fmt.Errorf("Invalid email address. email: %s", addr))
		}
	}
	return
}

// Validate SMTP configuration
func (c *SMTPConf) Validate() (errs []error) {
	if !Conf.ToEmail {
		return
	}
	// Check Emails fromat
	emails := []string{}
	emails = append(emails, c.From)
	emails = append(emails, c.To...)
	emails = append(emails, c.Cc...)

	if emailErrs := checkEmails(emails); 0 < len(emailErrs) {
		errs = append(errs, emailErrs...)
	}

	if len(c.SMTPAddr) == 0 {
		errs = append(errs, fmt.Errorf("email.smtpAddr must not be empty"))
	}
	if len(c.SMTPPort) == 0 {
		errs = append(errs, fmt.Errorf("email.smtpPort must not be empty"))
	}
	if len(c.To) == 0 {
		errs = append(errs, fmt.Errorf("email.To required at least one address"))
	}
	if len(c.From) == 0 {
		errs = append(errs, fmt.Errorf("email.From required at least one address"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}

// StrideConf is stride config
type StrideConf struct {
	HookURL   string `json:"hook_url"`
	AuthToken string `json:"AuthToken"`
}

// Validate validates configuration
func (c *StrideConf) Validate() (errs []error) {
	if !Conf.ToStride {
		return
	}

	if len(c.HookURL) == 0 {
		errs = append(errs, fmt.Errorf("stride.HookURL must not be empty"))
	}

	if len(c.AuthToken) == 0 {
		errs = append(errs, fmt.Errorf("stride.AuthToken must not be empty"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}

// SlackConf is slack config
type SlackConf struct {
	HookURL     string   `valid:"url" json:"-" toml:"hookURL,omitempty"`
	LegacyToken string   `json:"token" toml:"legacyToken,omitempty"`
	Channel     string   `json:"channel" toml:"channel,omitempty"`
	IconEmoji   string   `json:"icon_emoji" toml:"iconEmoji,omitempty"`
	AuthUser    string   `json:"username" toml:"authUser,omitempty"`
	NotifyUsers []string `toml:"notifyUsers,omitempty"`
	Text        string   `json:"text"`
}

// Validate validates configuration
func (c *SlackConf) Validate() (errs []error) {
	if !Conf.ToSlack {
		return
	}

	if len(c.HookURL) == 0 && len(c.LegacyToken) == 0 {
		errs = append(errs, fmt.Errorf("slack.hookURL or slack.LegacyToken must not be empty"))
	}

	if len(c.Channel) == 0 {
		errs = append(errs, fmt.Errorf("slack.channel must not be empty"))
	} else {
		if !(strings.HasPrefix(c.Channel, "#") ||
			c.Channel == "${servername}") {
			errs = append(errs, fmt.Errorf(
				"channel's prefix must be '#', channel: %s", c.Channel))
		}
	}

	if len(c.AuthUser) == 0 {
		errs = append(errs, fmt.Errorf("slack.authUser must not be empty"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	return
}

// HipChatConf is HipChat config
type HipChatConf struct {
	AuthToken string `json:"AuthToken"`
	Room      string `json:"Room"`
}

// Validate validates configuration
func (c *HipChatConf) Validate() (errs []error) {
	if !Conf.ToHipChat {
		return
	}
	if len(c.Room) == 0 {
		errs = append(errs, fmt.Errorf("hipcaht.room must not be empty"))
	}

	if len(c.AuthToken) == 0 {
		errs = append(errs, fmt.Errorf("hipcaht.AuthToken must not be empty"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}

// ChatWorkConf is ChatWork config
type ChatWorkConf struct {
	APIToken string `json:"ApiToken"`
	Room     string `json:"Room"`
}

// Validate validates configuration
func (c *ChatWorkConf) Validate() (errs []error) {
	if !Conf.ToChatWork {
		return
	}
	if len(c.Room) == 0 {
		errs = append(errs, fmt.Errorf("chatworkcaht.room must not be empty"))
	}

	if len(c.APIToken) == 0 {
		errs = append(errs, fmt.Errorf("chatworkcaht.ApiToken must not be empty"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}

// SyslogConf is syslog config
type SyslogConf struct {
	Protocol string
	Host     string `valid:"host"`
	Port     string `valid:"port"`
	Severity string
	Facility string
	Tag      string

	Verbose bool
}

// Validate validates configuration
func (c *SyslogConf) Validate() (errs []error) {
	if !Conf.ToSyslog {
		return nil
	}
	//  If protocol is empty, it will connect to the local syslog server.
	if len(c.Protocol) > 0 && c.Protocol != "tcp" && c.Protocol != "udp" {
		errs = append(errs, errors.New(`syslog.protocol must be "tcp" or "udp"`))
	}

	// Default port: 514
	if c.Port == "" {
		c.Port = "514"
	}

	if _, err := c.GetSeverity(); err != nil {
		errs = append(errs, err)
	}

	if _, err := c.GetFacility(); err != nil {
		errs = append(errs, err)
	}

	if _, err := valid.ValidateStruct(c); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// GetSeverity gets severity
func (c *SyslogConf) GetSeverity() (syslog.Priority, error) {
	if c.Severity == "" {
		return syslog.LOG_INFO, nil
	}

	switch c.Severity {
	case "emerg":
		return syslog.LOG_EMERG, nil
	case "alert":
		return syslog.LOG_ALERT, nil
	case "crit":
		return syslog.LOG_CRIT, nil
	case "err":
		return syslog.LOG_ERR, nil
	case "warning":
		return syslog.LOG_WARNING, nil
	case "notice":
		return syslog.LOG_NOTICE, nil
	case "info":
		return syslog.LOG_INFO, nil
	case "debug":
		return syslog.LOG_DEBUG, nil
	default:
		return -1, fmt.Errorf("Invalid severity: %s", c.Severity)
	}
}

// GetFacility gets facility
func (c *SyslogConf) GetFacility() (syslog.Priority, error) {
	if c.Facility == "" {
		return syslog.LOG_AUTH, nil
	}

	switch c.Facility {
	case "kern":
		return syslog.LOG_KERN, nil
	case "user":
		return syslog.LOG_USER, nil
	case "mail":
		return syslog.LOG_MAIL, nil
	case "daemon":
		return syslog.LOG_DAEMON, nil
	case "auth":
		return syslog.LOG_AUTH, nil
	case "syslog":
		return syslog.LOG_SYSLOG, nil
	case "lpr":
		return syslog.LOG_LPR, nil
	case "news":
		return syslog.LOG_NEWS, nil
	case "uucp":
		return syslog.LOG_UUCP, nil
	case "cron":
		return syslog.LOG_CRON, nil
	case "authpriv":
		return syslog.LOG_AUTHPRIV, nil
	case "ftp":
		return syslog.LOG_FTP, nil
	case "local0":
		return syslog.LOG_LOCAL0, nil
	case "local1":
		return syslog.LOG_LOCAL1, nil
	case "local2":
		return syslog.LOG_LOCAL2, nil
	case "local3":
		return syslog.LOG_LOCAL3, nil
	case "local4":
		return syslog.LOG_LOCAL4, nil
	case "local5":
		return syslog.LOG_LOCAL5, nil
	case "local6":
		return syslog.LOG_LOCAL6, nil
	case "local7":
		return syslog.LOG_LOCAL7, nil
	default:
		return -1, fmt.Errorf("Invalid facility: %s", c.Facility)
	}
}

// ServerInfo has SSH Info, additional CPE packages to scan.
type ServerInfo struct {
	ServerName  string `toml:"-"`
	User        string `toml:"user,omitempty"`
	Host        string `toml:"host,omitempty"`
	Port        string `toml:"port,omitempty"`
	KeyPath     string `toml:"keyPath,omitempty"`
	KeyPassword string `json:"-" toml:"-"`
	// TODO Deprecated remove in near future
	CpeNames []string `toml:"cpeNames,omitempty" json:",omitempty"`
	CpeURIs  []string `toml:"cpeURIs,omitempty" json:",omitempty"`
	ScanMode []string `toml:"scanMode,omitempty" json:",omitempty"`
	// TODO Deprecated remove in near future
	DependencyCheckXMLPath string `toml:"dependencyCheckXMLPath,omitempty"`
	OwaspDCXMLPath         string `toml:"owaspDCXMLPath,omitempty"`

	ContainersIncluded []string `toml:"containersIncluded,omitempty" json:",omitempty"`
	ContainersExcluded []string `toml:"containersExcluded,omitempty" json:",omitempty"`
	ContainerType      string   `toml:"containerType,omitempty" json:",omitempty"`
	Containers         map[string]ContainerSetting

	IgnoreCves       []string `toml:"ignoreCves,omitempty" json:",omitempty"`
	IgnorePkgsRegexp []string `toml:"ignorePkgsRegexp,omitempty" json:",omitempty"`

	UUIDs map[string]string `toml:"uuids,omitempty" json:",omitempty"`
	Memo  string            `toml:"memo,omitempty"`

	// For CentOS, RHEL, Amazon
	Enablerepo []string `toml:",omitempty" json:",omitempty"`

	// Optional key-value set that will be outputted to JSON
	Optional map[string]interface{} `toml:",omitempty" json:",omitempty"`

	// "pseudo" or ""
	Type string

	// used internal
	LogMsgAnsiColor string    `toml:"-"` // DebugLog Color
	Container       Container `toml:"-"`
	Distro          Distro    `toml:"-"`
	Mode            ScanMode  `toml:"-"`

	// IP addresses
	IPv4Addrs []string `toml:"-" json:",omitempty"`
	IPv6Addrs []string `toml:"-" json:",omitempty"`
}

// ContainerSetting is used for loading container setting in config.toml
type ContainerSetting struct {
	CpeURIs          []string
	OwaspDCXMLPath   string
	IgnorePkgsRegexp []string
	IgnoreCves       []string
}

// ScanMode has a type of scan mode. fast, fast-root, deep and offline
type ScanMode struct {
	flag byte
}

// Set mode
func (s *ScanMode) Set(f byte) {
	s.flag |= f
}

// IsFast return whether scan mode is fast
func (s ScanMode) IsFast() bool {
	return s.flag&Fast == Fast
}

// IsFastRoot return whether scan mode is fastroot
func (s ScanMode) IsFastRoot() bool {
	return s.flag&FastRoot == FastRoot
}

// IsDeep return whether scan mode is deep
func (s ScanMode) IsDeep() bool {
	return s.flag&Deep == Deep
}

// IsOffline return whether scan mode is offline
func (s ScanMode) IsOffline() bool {
	return s.flag&Offline == Offline
}

func (s ScanMode) validate() error {
	numTrue := 0
	for _, b := range []bool{s.IsFast(), s.IsFastRoot(), s.IsDeep()} {
		if b {
			numTrue++
		}
	}
	if numTrue == 0 {
		s.Set(Fast)
	} else if s.IsDeep() && s.IsOffline() {
		return fmt.Errorf("Don't specify both of -deep and offline")
	} else if numTrue != 1 {
		return fmt.Errorf("Specify only one of -fast, -fast-root or -deep")
	}
	return nil
}

func (s ScanMode) String() string {
	ss := ""
	if s.IsFast() {
		ss = "fast"
	} else if s.IsFastRoot() {
		ss = "fast-root"
	} else if s.IsDeep() {
		ss = "deep"
	}
	if s.IsOffline() {
		ss += " offline"
	}
	return ss + " mode"
}

const (
	// Fast is fast scan mode
	Fast = byte(1 << iota)
	// FastRoot is fast-root scan mode
	FastRoot
	// Deep is deep scan mode
	Deep
	// Offline is offline scan mode
	Offline
)

// GetServerName returns ServerName if this serverInfo is about host.
// If this serverInfo is abount a container, returns containerID@ServerName
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
func (l Distro) MajorVersion() (ver int, err error) {
	if l.Family == Amazon {
		ss := strings.Fields(l.Release)
		if len(ss) == 1 {
			return 1, nil
		}
		ver, err = strconv.Atoi(ss[0])
		return
	}
	if 0 < len(l.Release) {
		ver, err = strconv.Atoi(strings.Split(l.Release, ".")[0])
	} else {
		err = fmt.Errorf("Release is empty")
	}
	return
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
