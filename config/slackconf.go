package config

import (
	"strings"

	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// SlackConf is slack config
type SlackConf struct {
	HookURL     string   `valid:"url" json:"-" toml:"hookURL,omitempty"`
	LegacyToken string   `json:"-" toml:"legacyToken,omitempty"`
	Channel     string   `json:"-" toml:"channel,omitempty"`
	IconEmoji   string   `json:"-" toml:"iconEmoji,omitempty"`
	AuthUser    string   `json:"-" toml:"authUser,omitempty"`
	NotifyUsers []string `toml:"notifyUsers,omitempty" json:"-"`
	Text        string   `json:"-"`
	Enabled     bool     `toml:"-" json:"-"`
}

// Validate validates configuration
func (c *SlackConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}

	if len(c.HookURL) == 0 && len(c.LegacyToken) == 0 {
		errs = append(errs, xerrors.New("slack.hookURL or slack.LegacyToken must not be empty"))
	}

	if len(c.Channel) == 0 {
		errs = append(errs, xerrors.New("slack.channel must not be empty"))
	} else {
		if !(strings.HasPrefix(c.Channel, "#") ||
			c.Channel == "${servername}") {
			errs = append(errs, xerrors.Errorf(
				"channel's prefix must be '#', channel: %s", c.Channel))
		}
	}

	if len(c.AuthUser) == 0 {
		errs = append(errs, xerrors.New("slack.authUser must not be empty"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}

	return
}
