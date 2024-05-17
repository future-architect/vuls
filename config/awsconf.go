package config

import (
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

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

	// report s3 enable
	Enabled bool `toml:"-" json:"-"`
}

// Validate configuration
func (c *AWSConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}

	if c.S3Bucket == "" {
		errs = append(errs, fmt.Errorf("S3Bucket is empty"))

	}

	if c.S3ServerSideEncryption != "" {
		if !slices.Contains(s3.PutObjectInput{}.ServerSideEncryption.Values(), types.ServerSideEncryption(c.S3ServerSideEncryption)) {
			errs = append(errs, fmt.Errorf("S3ServerSideEncryption: %s is not supported server side encryption type", c.S3ServerSideEncryption))
		}
	}

	return
}
