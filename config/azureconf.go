package config

import (
	"os"

	"golang.org/x/xerrors"
)

// AzureConf is azure config
type AzureConf struct {
	// Azure account name to use. AZURE_STORAGE_ACCOUNT environment variable is used if not specified
	AccountName string `json:"accountName"`

	// Azure account key to use. AZURE_STORAGE_ACCESS_KEY environment variable is used if not specified
	AccountKey string `json:"-"`

	// Azure storage container name
	ContainerName string `json:"containerName"`

	Enabled bool `toml:"-" json:"-"`
}

// Validate configuration
func (c *AzureConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}
	if c.AccountName == "" {
		c.AccountName = os.Getenv("AZURE_STORAGE_ACCOUNT")
	}

	if c.AccountKey == "" {
		c.AccountKey = os.Getenv("AZURE_STORAGE_ACCESS_KEY")
	}
	if c.ContainerName == "" {
		errs = append(errs, xerrors.Errorf("Azure storage container name is required"))
	}
	return
}
