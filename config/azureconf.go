package config

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
	// TODO
	if !c.Enabled {
		return
	}
	return
}
