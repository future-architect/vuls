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
	Debug                  bool                  `json:"debug"`
	DebugSQL               bool                  `json:"debugSQL"`
	Lang                   string                `json:"lang"`
	EMail                  SMTPConf              `json:"-"`
	Slack                  SlackConf             `json:"-"`
	Stride                 StrideConf            `json:"-"`
	HipChat                HipChatConf           `json:"-"`
	ChatWork               ChatWorkConf          `json:"-"`
	Syslog                 SyslogConf            `json:"-"`
	HTTP                   HTTPConf              `json:"-"`
	Default                ServerInfo            `json:"default"`
	Servers                map[string]ServerInfo `json:"servers"`
	CvssScoreOver          float64               `json:"cvssScoreOver"`
	IgnoreUnscoredCves     bool                  `json:"ignoreUnscoredCves"`
	IgnoreUnfixed          bool                  `json:"ignoreUnfixed"`
	SSHNative              bool                  `json:"sshNative"`
	SSHConfig              bool                  `json:"sshConfig"`
	ContainersOnly         bool                  `json:"containersOnly"`
	SkipBroken             bool                  `json:"skipBroken"`
	HTTPProxy              string                `valid:"url" json:"httpProxy"`
	LogDir                 string                `json:"logDir"`
	ResultsDir             string                `json:"resultsDir"`
	CveDBType              string                `json:"cveDBType"`
	CveDBPath              string                `json:"cveDBPath"`
	CveDBURL               string                `json:"cveDBURL"`
	OvalDBType             string                `json:"ovalDBType"`
	OvalDBPath             string                `json:"ovalDBPath"`
	OvalDBURL              string                `json:"ovalDBURL"`
	GostDBType             string                `json:"gostDBType"`
	GostDBPath             string                `json:"gostDBPath"`
	GostDBURL              string                `json:"gostDBURL"`
	CacheDBPath            string                `json:"cacheDBPath"`
	RefreshCve             bool                  `json:"refreshCve"`
	ToSlack                bool                  `json:"toSlack"`
	ToStride               bool                  `json:"toStride"`
	ToHipChat              bool                  `json:"toHipChat"`
	ToChatWork             bool                  `json:"toChatWork"`
	ToEmail                bool                  `json:"toEmail"`
	ToSyslog               bool                  `json:"toSyslog"`
	ToLocalFile            bool                  `json:"toLocalFile"`
	ToS3                   bool                  `json:"toS3"`
	ToAzureBlob            bool                  `json:"toAzureBlob"`
	ToHTTP                 bool                  `json:"toHTTP"`
	FormatXML              bool                  `json:"formatXML"`
	FormatJSON             bool                  `json:"formatJSON"`
	FormatOneEMail         bool                  `json:"formatOneEMail"`
	FormatOneLineText      bool                  `json:"formatOneLineText"`
	FormatList             bool                  `json:"formatList"`
	FormatFullText         bool                  `json:"formatFullText"`
	GZIP                   bool                  `json:"gzip"`
	AwsProfile             string                `json:"awsProfile"`
	AwsRegion              string                `json:"awsRegion"`
	S3Bucket               string                `json:"s3Bucket"`
	S3ResultsDir           string                `json:"s3ResultsDir"`
	S3ServerSideEncryption string                `json:"s3ServerSideEncryption"`
	AzureAccount           string                `json:"azureAccount"`
	AzureKey               string                `json:"-"`
	AzureContainer         string                `json:"azureContainer"`
	Pipe                   bool                  `json:"pipe"`
	Vvv                    bool                  `json:"vvv"`
	Diff                   bool                  `json:"diff"`
	UUID                   bool                  `json:"uuid"`
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
	SMTPAddr      string   `toml:"smtpAddr,omitempty" json:"-"`
	SMTPPort      string   `toml:"smtpPort,omitempty" valid:"port" json:"-"`
	User          string   `toml:"user,omitempty" json:"-"`
	Password      string   `toml:"password,omitempty" json:"-"`
	From          string   `toml:"from,omitempty" json:"-"`
	To            []string `toml:"to,omitempty" json:"-"`
	Cc            []string `toml:"cc,omitempty" json:"-"`
	SubjectPrefix string   `toml:"subjectPrefix,omitempty" json:"-"`
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
	HookURL   string `json:"-"`
	AuthToken string `json:"-"`
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
	LegacyToken string   `json:"-" toml:"legacyToken,omitempty"`
	Channel     string   `json:"-" toml:"channel,omitempty"`
	IconEmoji   string   `json:"-" toml:"iconEmoji,omitempty"`
	AuthUser    string   `json:"-" toml:"authUser,omitempty"`
	NotifyUsers []string `toml:"notifyUsers,omitempty" json:"-"`
	Text        string   `json:"-"`
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
	AuthToken string `json:"-"`
	Room      string `json:"-"`
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
	APIToken string `json:"-"`
	Room     string `json:"-"`
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
	Protocol string `json:"-"`
	Host     string `valid:"host" json:"-"`
	Port     string `valid:"port" json:"-"`
	Severity string `json:"-"`
	Facility string `json:"-"`
	Tag      string `json:"-"`
	Verbose  bool   `json:"-"`
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

// HTTPConf is HTTP config
type HTTPConf struct {
	URL string `valid:"url" json:"-"`
}

// Validate validates configuration
func (c *HTTPConf) Validate() (errs []error) {
	if !Conf.ToHTTP {
		return nil
	}

	if _, err := valid.ValidateStruct(c); err != nil {
		errs = append(errs, err)
	}
	return errs
}

// ServerInfo has SSH Info, additional CPE packages to scan.
type ServerInfo struct {
	ServerName             string                      `toml:"-" json:"serverName"`
	User                   string                      `toml:"user,omitempty" json:"user"`
	Host                   string                      `toml:"host,omitempty" json:"host"`
	Port                   string                      `toml:"port,omitempty" json:"port"`
	KeyPath                string                      `toml:"keyPath,omitempty" json:"keyPath"`
	KeyPassword            string                      `json:"-" toml:"-"`
	CpeNames               []string                    `toml:"cpeNames,omitempty" json:"-"` // TODO Deprecated remove in near future
	CpeURIs                []string                    `toml:"cpeURIs,omitempty" json:"cpeURIs,omitempty"`
	ScanMode               []string                    `toml:"scanMode,omitempty" json:"scanMode,omitempty"`
	DependencyCheckXMLPath string                      `toml:"dependencyCheckXMLPath,omitempty" json:"-"` // TODO Deprecated remove in near future
	OwaspDCXMLPath         string                      `toml:"owaspDCXMLPath,omitempty" json:"owaspDCXMLPath"`
	ContainersIncluded     []string                    `toml:"containersIncluded,omitempty" json:"containersIncluded,omitempty"`
	ContainersExcluded     []string                    `toml:"containersExcluded,omitempty" json:"containersExcluded,omitempty"`
	ContainerType          string                      `toml:"containerType,omitempty" json:"containerType,omitempty"`
	Containers             map[string]ContainerSetting `toml:"containers" json:"containers,omitempty"`
	IgnoreCves             []string                    `toml:"ignoreCves,omitempty" json:"ignoreCves,omitempty"`
	IgnorePkgsRegexp       []string                    `toml:"ignorePkgsRegexp,omitempty" json:"ignorePkgsRegexp,omitempty"`
	UUIDs                  map[string]string           `toml:"uuids,omitempty" json:"uuids,omitempty"`
	Memo                   string                      `toml:"memo,omitempty" json:"memo"`
	Enablerepo             []string                    `toml:"enablerepo,omitempty" json:"enablerepo,omitempty"` // For CentOS, RHEL, Amazon
	Optional               map[string]interface{}      `toml:"optional,omitempty" json:"optional,omitempty"`     // Optional key-value set that will be outputted to JSON
	Type                   string                      `toml:"type,omitempty" json:"type"`                       // "pseudo" or ""
	IPv4Addrs              []string                    `toml:"-" json:"ipv4Addrs,omitempty"`
	IPv6Addrs              []string                    `toml:"-" json:"ipv6Addrs,omitempty"`

	// used internal
	LogMsgAnsiColor string    `toml:"-" json:"-"` // DebugLog Color
	Container       Container `toml:"-" json:"-"`
	Distro          Distro    `toml:"-" json:"-"`
	Mode            ScanMode  `toml:"-" json:"-"`
}

// ContainerSetting is used for loading container setting in config.toml
type ContainerSetting struct {
	CpeURIs          []string `json:"cpeURIs,omitempty"`
	OwaspDCXMLPath   string   `json:"owaspDCXMLPath"`
	IgnorePkgsRegexp []string `json:"ignorePkgsRegexp,omitempty"`
	IgnoreCves       []string `json:"ignoreCves,omitempty"`
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
