package config

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// GoogleChatConf is GoogleChat config
type GoogleChatConf struct {
	WebHookURL  string `json:"-" toml:"webHookURL,omitempty"`
	SkipHealthy bool   `json:"-" toml:"skipHealthy"`
	Filter      string `json:"-" toml:"filter,omitempty"`
	Enabled     bool   `json:"-" toml:"-"`
}

// Validate validates configuration
func (c *GoogleChatConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}
	if len(c.WebHookURL) == 0 {
		errs = append(errs, xerrors.New("googleChatConf.webHookURL must not be empty"))
	}
	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
