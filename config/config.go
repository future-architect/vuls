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
	"runtime"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	valid "github.com/asaskevich/govalidator"
)

// Conf has Configuration
var Conf Config

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

	SSHNative       bool
	ContainersOnly  bool
	PackageListOnly bool
	SkipBroken      bool

	HTTPProxy  string `valid:"url"`
	LogDir     string
	ResultsDir string

	CveDBType   string
	CveDBPath   string
	CveDBURL    string
	CacheDBPath string

	OvalDBType string
	OvalDBPath string

	FormatXML         bool
	FormatJSON        bool
	FormatOneEMail    bool
	FormatOneLineText bool
	FormatShortText   bool
	FormatFullText    bool

	GZIP bool

	AwsProfile string
	AwsRegion  string
	S3Bucket   string

	AzureAccount   string
	AzureKey       string
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

	switch c.CveDBType {
	case "sqlite3":
		if ok, _ := valid.IsFilePath(c.CveDBPath); !ok {
			errs = append(errs, fmt.Errorf(
				"SQLite3 DB(CVE-Dictionary) path must be a *Absolute* file path. -cvedb-path: %s",
				c.CveDBPath))
		}
	case "mysql":
		if c.CveDBURL == "" {
			errs = append(errs, fmt.Errorf(
				`MySQL connection string is needed. -cvedb-url="user:pass@tcp(localhost:3306)/dbname"`))
		}
	default:
		errs = append(errs, fmt.Errorf(
			"CVE DB type must be either 'sqlite3' or 'mysql'.  -cvedb-type: %s", c.CveDBType))
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

	if c.CveDBType != "sqlite3" && c.CveDBType != "mysql" {
		errs = append(errs, fmt.Errorf(
			"CVE DB type must be either 'sqlite3' or 'mysql'.  -cve-dictionary-dbtype: %s", c.CveDBType))
	}

	if c.CveDBType == "sqlite3" {
		if ok, _ := valid.IsFilePath(c.CveDBPath); !ok {
			errs = append(errs, fmt.Errorf(
				"SQLite3 DB(CVE-Dictionary) path must be a *Absolute* file path. -cve-dictionary-dbpath: %s", c.CveDBPath))
		}
	}

	for _, err := range errs {
		log.Error(err)
	}

	return len(errs) == 0
}

// SMTPConf is smtp config
type SMTPConf struct {
	SMTPAddr string
	SMTPPort string `valid:"port"`

	User          string
	Password      string
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
	HookURL   string `valid:"url"`
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
	KeyPassword string

	CpeNames               []string
	DependencyCheckXMLPath string

	// Container Names or IDs
	Containers Containers

	IgnoreCves []string

	// Optional key-value set that will be outputted to JSON
	Optional [][]interface{}

	// For CentOS, RHEL, Amazon
	Enablerepo string

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
