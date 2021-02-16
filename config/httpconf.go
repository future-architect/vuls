package config

import (
	"os"

	"github.com/asaskevich/govalidator"
)

// HTTPConf is HTTP config
type HTTPConf struct {
	URL     string `valid:"url" json:"-"`
	Enabled bool   `toml:"-" json:"-"`
}

// Validate validates configuration
func (c *HTTPConf) Validate() (errs []error) {
	if !c.Enabled {
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
func (c *HTTPConf) Init(url string) {
	if os.Getenv(httpKey) != "" {
		c.URL = os.Getenv(httpKey)
	}
	if url != "" {
		c.URL = url
	}
}
