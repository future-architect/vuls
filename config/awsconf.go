package config

// AWSConf is aws config
type AWSConf struct {
	// AWS profile to use
	Profile string `json:"profile"`

	// AWS region to use
	Region string `json:"region"`

	// S3 bucket name
	S3Bucket string `json:"s3Bucket"`

	// /bucket/path/to/results
	S3ResultsDir string `json:"s3ResultsDir"`

	// The Server-side encryption algorithm used when storing the reports in S3 (e.g., AES256, aws:kms).
	S3ServerSideEncryption string `json:"s3ServerSideEncryption"`

	Enabled bool `toml:"-" json:"-"`
}

// Validate configuration
func (c *AWSConf) Validate() (errs []error) {
	// TODO
	if !c.Enabled {
		return
	}
	return
}
