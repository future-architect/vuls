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

const httpKey = "VULS_HTTP_URL"

// Validate validates configuration
func (c *HTTPConf) Validate() (errs []error) {
	if !c.Enabled {
		return nil
	}

	// overwrite if env var is not empty
	if os.Getenv(httpKey) != "" {
		c.URL = os.Getenv(httpKey)
	}

	if _, err := govalidator.ValidateStruct(c); err != nil {
		errs = append(errs, err)
	}
	return errs
}
