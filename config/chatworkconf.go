package config

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// ChatWorkConf is ChatWork config
type ChatWorkConf struct {
	APIToken string `json:"-"`
	Room     string `json:"-"`
	Enabled  bool   `toml:"-" json:"-"`
}

// Validate validates configuration
func (c *ChatWorkConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}
	if len(c.Room) == 0 {
		errs = append(errs, xerrors.New("chatWorkConf.room must not be empty"))
	}

	if len(c.APIToken) == 0 {
		errs = append(errs, xerrors.New("chatWorkConf.ApiToken must not be empty"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
