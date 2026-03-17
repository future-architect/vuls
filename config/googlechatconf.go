package config

import (
	"errors"

	"github.com/asaskevich/govalidator"
)

// GoogleChatConf is GoogleChat config
type GoogleChatConf struct {
	WebHookURL       string `valid:"url" json:"-" toml:"webHookURL,omitempty"`
	SkipIfNoCve      bool   `valid:"type(bool)" json:"-" toml:"skipIfNoCve"`
	ServerNameRegexp string `valid:"type(string)" json:"-" toml:"serverNameRegexp,omitempty"`
	Enabled          bool   `valid:"type(bool)" json:"-" toml:"-"`
}

// Validate validates configuration
func (c *GoogleChatConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}
	if len(c.WebHookURL) == 0 {
		errs = append(errs, errors.New("googleChatConf.webHookURL must not be empty"))
	}
	if !govalidator.IsRegex(c.ServerNameRegexp) {
		errs = append(errs, errors.New("googleChatConf.serverNameRegexp must be regex"))
	}
	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
