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
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"

	valid "github.com/asaskevich/govalidator"
	log "github.com/sirupsen/logrus"
)

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
)

//Config is struct of Configuration
type Config struct {
	Debug    bool
	DebugSQL bool
	Lang     string

	EMail   SMTPConf
	Slack   SlackConf
	Default ServerInfo
	Servers map[string]ServerInfo

	CvssScoreOver      float64
	IgnoreUnscoredCves bool

	SSHNative      bool
	ContainersOnly bool
	Deep           bool
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

	FormatXML         bool
	FormatJSON        bool
	FormatOneEMail    bool
	FormatOneLineText bool
	FormatShortText   bool
	FormatFullText    bool

	GZIP bool

	AwsProfile   string
	AwsRegion    string
	S3Bucket     string
	S3ResultsDir string

	AzureAccount   string
	AzureKey       string `json:"-"`
	AzureContainer string

	Pipe bool
	Diff bool
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

// ValidateOnPrepare validates configuration
func (c Config) ValidateOnPrepare() bool {
	return c.ValidateOnConfigtest()
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
	SMTPAddr string
	SMTPPort string `valid:"port"`

	User          string
	Password      string `json:"-"`
	From          string
	To            []string
	Cc            []string
	SubjectPrefix string

	UseThisTime bool
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

	if !c.UseThisTime {
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
		errs = append(errs, fmt.Errorf("smtpAddr must not be empty"))
	}
	if len(c.SMTPPort) == 0 {
		errs = append(errs, fmt.Errorf("smtpPort must not be empty"))
	}
	if len(c.To) == 0 {
		errs = append(errs, fmt.Errorf("To required at least one address"))
	}
	if len(c.From) == 0 {
		errs = append(errs, fmt.Errorf("From required at least one address"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}

// SlackConf is slack config
type SlackConf struct {
	HookURL   string `valid:"url" json:"-"`
	Channel   string `json:"channel"`
	IconEmoji string `json:"icon_emoji"`
	AuthUser  string `json:"username"`

	NotifyUsers []string
	Text        string `json:"text"`

	UseThisTime bool
}

// Validate validates configuration
func (c *SlackConf) Validate() (errs []error) {
	if !c.UseThisTime {
		return
	}

	if len(c.HookURL) == 0 {
		errs = append(errs, fmt.Errorf("hookURL must not be empty"))
	}

	if len(c.Channel) == 0 {
		errs = append(errs, fmt.Errorf("channel must not be empty"))
	} else {
		if !(strings.HasPrefix(c.Channel, "#") ||
			c.Channel == "${servername}") {
			errs = append(errs, fmt.Errorf(
				"channel's prefix must be '#', channel: %s", c.Channel))
		}
	}

	if len(c.AuthUser) == 0 {
		errs = append(errs, fmt.Errorf("authUser must not be empty"))
	}

	_, err := valid.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	return
}

// ServerInfo has SSH Info, additional CPE packages to scan.
type ServerInfo struct {
	ServerName  string
	User        string
	Host        string
	Port        string
	KeyPath     string
	KeyPassword string `json:"-"`

	CpeNames               []string
	DependencyCheckXMLPath string

	// Container Names or IDs
	Containers Containers

	IgnoreCves []string

	// Optional key-value set that will be outputted to JSON
	Optional [][]interface{}

	// For CentOS, RHEL, Amazon
	Enablerepo []string

	// used internal
	LogMsgAnsiColor string // DebugLog Color
	Container       Container
	Distro          Distro
}

// GetServerName returns ServerName if this serverInfo is about host.
// If this serverInfo is abount a container, returns containerID@ServerName
func (s ServerInfo) GetServerName() string {
	if len(s.Container.ContainerID) == 0 {
		return s.ServerName
	}
	return fmt.Sprintf("%s@%s", s.Container.ContainerID, s.ServerName)
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

// Containers has Containers information.
type Containers struct {
	Type     string
	Includes []string
	Excludes []string
}

// Container has Container information.
type Container struct {
	ContainerID string
	Name        string
	Image       string
}
