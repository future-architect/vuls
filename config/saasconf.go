package config

import (
	"errors"

	"github.com/asaskevich/govalidator"
)

// SaasConf is FutureVuls config
type SaasConf struct {
	GroupID int64  `json:"GroupID"`
	Token   string `json:"Token"`
	URL     string `json:"URL"`
}

// Validate validates configuration
func (c *SaasConf) Validate() (errs []error) {
	if c.GroupID == 0 {
		errs = append(errs, errors.New("GroupID must not be empty"))
	}

	if len(c.Token) == 0 {
		errs = append(errs, errors.New("Token must not be empty"))
	}

	if len(c.URL) == 0 {
		errs = append(errs, errors.New("URL must not be empty"))
	}

	_, err := govalidator.ValidateStruct(c)
	if err != nil {
		errs = append(errs, err)
	}
	return
}
