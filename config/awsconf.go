package config

import (
	"fmt"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// AWSConf is aws config
type AWSConf struct {
	// AWS S3 Endpoint to use
	S3Endpoint string `json:"s3Endpoint"`

	// AWS region to use
	Region string `json:"region"`

	// AWS profile to use
	Profile string `json:"profile"`

	// AWS config files to use
	ConfigFiles []string `json:"configFiles"`

	// AWS credential files to use
	CredentialFiles []string `json:"credentialFiles"`

	// use credential provider
	CredentialProvider CredentialProviderType `json:"credentialProvider"`

	// The access key ID that identifies the temporary security credentials. (credential provider type: static only)
	AccessKeyID string `json:"accessKeyID"`

	// The secret access key that can be used to sign requests. (credential provider type: static only)
	SecretAccessKey string `json:"secretAccessKey"`

	// The token that users must pass to the service API to use the temporary (credential provider type: static only)
	SessionToken string `json:"sessionToken"`

	// endpoint for credential provider (credential provider type: endpoint only)
	CredentialEndpoint string `json:"credentialEndpoint"`

	// S3 bucket name
	S3Bucket string `json:"s3Bucket"`

	// /bucket/path/to/results
	S3ResultsDir string `json:"s3ResultsDir"`

	// The Server-side encryption algorithm used when storing the reports in S3 (e.g., AES256, aws:kms).
	S3ServerSideEncryption string `json:"s3ServerSideEncryption"`

	// use s3 path style
	S3UsePathStyle bool `json:"s3UsePathStyle"`

	// report s3 enable
	Enabled bool `toml:"-" json:"-"`
}

// CredentialProviderType is credential provider type
type CredentialProviderType string

const (
	// CredentialProviderAnonymous is credential provider type: anonymous
	CredentialProviderAnonymous CredentialProviderType = "anonymous"
	// CredentialProviderEC2Metadata is credential provider type: ec2metadata
	CredentialProviderEC2Metadata CredentialProviderType = "ec2metadata"
	// CredentialProviderStatic is credential provider type: static
	CredentialProviderStatic CredentialProviderType = "static"
	// CredentialProviderEndpoint is credential provider type: endpoint
	CredentialProviderEndpoint CredentialProviderType = "endpoint"
)

// Validate configuration
func (c *AWSConf) Validate() (errs []error) {
	if !c.Enabled {
		return
	}

	switch c.CredentialProvider {
	case CredentialProviderType(""):
	case CredentialProviderAnonymous:
	case CredentialProviderEC2Metadata:
	case CredentialProviderStatic:
		if c.AccessKeyID == "" {
			errs = append(errs, fmt.Errorf("AccessKeyID is empty"))
		}
		if c.SecretAccessKey == "" {
			errs = append(errs, fmt.Errorf("SecretAccessKey is empty"))
		}
	case CredentialProviderEndpoint:
		if c.CredentialEndpoint == "" {
			errs = append(errs, fmt.Errorf("CredentialEndpoint is empty"))
		}
	default:
		errs = append(errs, fmt.Errorf("CredentialProvider: %s is not supported", c.CredentialProvider))
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
