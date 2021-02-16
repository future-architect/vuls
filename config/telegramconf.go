package config

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// TelegramConf is Telegram config
type TelegramConf struct {
	Token   string `json:"-"`
	ChatID  string `json:"-"`
	Enabled bool   `toml:"-" json:"-"`
}

// Validate validates configuration
func (c *TelegramConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}
	if len(c.ChatID) == 0 {
		errs = append(errs, xerrors.New("TelegramConf.ChatID must not be empty"))
	}

	if len(c.Token) == 0 {
		errs = append(errs, xerrors.New("TelegramConf.Token must not be empty"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
