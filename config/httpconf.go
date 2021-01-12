package config

import (
	"os"

	"github.com/asaskevich/govalidator"
)

// HTTPConf is HTTP config
type HTTPConf struct {
	URL string `valid:"url" json:"-"`
}

// Validate validates configuration
func (c *HTTPConf) Validate() (errs []error) {
	if !Conf.ToHTTP {
		return nil
	}

	if _, err := govalidator.ValidateStruct(c); err != nil {
		errs = append(errs, err)
	}
	return errs
}

const httpKey = "VULS_HTTP_URL"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (c *HTTPConf) Init(toml HTTPConf) {
	if os.Getenv(httpKey) != "" {
		c.URL = os.Getenv(httpKey)
	}
	if toml.URL != "" {
		c.URL = toml.URL
	}
}
