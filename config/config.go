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

	Mail    smtpConf
	Slack   SlackConf
	Default ServerInfo
	Servers map[string]ServerInfo

	CveDictionaryURL string `valid:"url"`

	CvssScoreOver      float64
	IgnoreUnscoredCves bool

	SSHExternal    bool
	ContainersOnly bool

	HTTPProxy   string `valid:"url"`
	ResultsDir  string
	CveDBPath   string
	CacheDBPath string

	AwsProfile string
	AwsRegion  string
	S3Bucket   string

	AzureAccount   string
	AzureKey       string
	AzureContainer string

	//  CpeNames      []string
	//  SummaryMode          bool
}

// Validate configuration
func (c Config) Validate() bool {
	errs := []error{}

	if len(c.ResultsDir) != 0 {
		if ok, _ := valid.IsFilePath(c.ResultsDir); !ok {
			errs = append(errs, fmt.Errorf(
				"JSON base directory must be a *Absolute* file path. -results-dir: %s", c.ResultsDir))
		}
	}

	if len(c.CveDBPath) != 0 {
		if ok, _ := valid.IsFilePath(c.CveDBPath); !ok {
			errs = append(errs, fmt.Errorf(
				"SQLite3 DB(Cve Dictionary) path must be a *Absolute* file path. -cve-dictionary-dbpath: %s", c.CveDBPath))
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

	if mailerrs := c.Mail.Validate(); 0 < len(mailerrs) {
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

// smtpConf is smtp config
type smtpConf struct {
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
func (c *smtpConf) Validate() (errs []error) {

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

	CpeNames []string

	// Container Names or IDs
	Containers []string

	IgnoreCves []string

	// Optional key-value set that will be outputted to JSON
	Optional [][]interface{}

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
	Type        string
}
