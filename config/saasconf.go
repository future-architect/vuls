package config

import (
	"github.com/asaskevich/govalidator"
	"golang.org/x/xerrors"
)

// SaasConf is FutureVuls config
type SaasConf struct {
	GroupID int64  `json:"-"`
	Token   string `json:"-"`
	URL     string `json:"-"`
}

// Validate validates configuration
func (c *SaasConf) Validate() (errs []error) {
	if c.GroupID == 0 {
		errs = append(errs, xerrors.New("GroupID must not be empty"))
	}

	if len(c.Token) == 0 {
		errs = append(errs, xerrors.New("Token must not be empty"))
	}

	if len(c.URL) == 0 {
		errs = append(errs, xerrors.New("URL must not be empty"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
