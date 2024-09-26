package reporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// S3Writer writes results to S3
type S3Writer struct {
	FormatJSON        bool
	FormatFullText    bool
	FormatOneLineText bool
	FormatList        bool
	Gzip              bool

	config.AWSConf
}

func (w S3Writer) getS3() (*s3.Client, error) {
	var optFns []func(*awsConfig.LoadOptions) error
	if w.Region != "" {
		optFns = append(optFns, awsConfig.WithRegion(w.Region))
	}
	if w.Profile != "" {
		optFns = append(optFns, awsConfig.WithSharedConfigProfile(w.Profile))
	}
	switch w.CredentialProvider {
	case "":
	case config.CredentialProviderAnonymous:
		optFns = append(optFns, awsConfig.WithCredentialsProvider(aws.AnonymousCredentials{}))
	default:
		return nil, xerrors.Errorf("CredentialProvider: %s is not supported", w.CredentialProvider)
	}
	cfg, err := awsConfig.LoadDefaultConfig(context.TODO(), optFns...)
	if err != nil {
		return nil, xerrors.Errorf("Failed to load config. err: %w", err)
	}
	return s3.NewFromConfig(cfg,
		func(o *s3.Options) {
			if w.S3Endpoint != "" {
				o.BaseEndpoint = aws.String(w.S3Endpoint)
			}
		},
		func(o *s3.Options) { o.UsePathStyle = w.S3UsePathStyle },
	), nil
}

// Write results to S3
// https://docs.aws.amazon.com/en_us/code-library/latest/ug/go_2_s3_code_examples.html
func (w S3Writer) Write(rs ...models.ScanResult) (err error) {
	if len(rs) == 0 {
		return nil
	}

	svc, err := w.getS3()
	if err != nil {
		return xerrors.Errorf("Failed to get s3 client. err: %w", err)
	}

	if w.FormatOneLineText {
		k := fmt.Sprintf("%s/summary.txt", rs[0].ScannedAt.Format(time.RFC3339))
		text := formatOneLineSummary(rs...)
		if err := w.putObject(svc, k, []byte(text), w.Gzip); err != nil {
			return err
		}
	}

	for _, r := range rs {
		key := r.ReportKeyName()
		if w.FormatJSON {
			k := key + ".json"
			var b []byte
			if b, err = json.Marshal(r); err != nil {
				return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
			}
			if err := w.putObject(svc, k, b, w.Gzip); err != nil {
				return err
			}
		}

		if w.FormatList {
			k := key + "_short.txt"
			text := formatList(r)
			if err := w.putObject(svc, k, []byte(text), w.Gzip); err != nil {
				return err
			}
		}

		if w.FormatFullText {
			k := key + "_full.txt"
			text := formatFullPlainText(r)
			if err := w.putObject(svc, k, []byte(text), w.Gzip); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrBucketExistCheck : bucket existence cannot be checked because s3:ListBucket or s3:ListAllMyBuckets is not allowed
var ErrBucketExistCheck = xerrors.New("bucket existence cannot be checked because s3:ListBucket or s3:ListAllMyBuckets is not allowed")

// Validate check the existence of S3 bucket
func (w S3Writer) Validate() error {
	svc, err := w.getS3()
	if err != nil {
		return xerrors.Errorf("Failed to get s3 client. err: %w", err)
	}

	// s3:ListBucket
	_, err = svc.HeadBucket(context.TODO(), &s3.HeadBucketInput{Bucket: aws.String(w.S3Bucket)})
	if err == nil {
		return nil
	}
	var nsb *types.NoSuchBucket
	if errors.As(err, &nsb) {
		return xerrors.Errorf("Failed to find the buckets. profile: %s, region: %s, bucket: %s", w.Profile, w.Region, w.S3Bucket)
	}

	// s3:ListAllMyBuckets
	result, err := svc.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	if err == nil {
		if slices.ContainsFunc(result.Buckets, func(b types.Bucket) bool {
			return *b.Name == w.S3Bucket
		}) {
			return nil
		}
		return xerrors.Errorf("Failed to find the buckets. profile: %s, region: %s, bucket: %s", w.Profile, w.Region, w.S3Bucket)
	}

	return ErrBucketExistCheck
}

func (w S3Writer) putObject(svc *s3.Client, k string, b []byte, gzip bool) error {
	var err error
	if gzip {
		if b, err = gz(b); err != nil {
			return err
		}
		k += ".gz"
	}

	putObjectInput := &s3.PutObjectInput{
		Bucket:               aws.String(w.S3Bucket),
		Key:                  aws.String(path.Join(w.S3ResultsDir, k)),
		Body:                 bytes.NewReader(b),
		ServerSideEncryption: types.ServerSideEncryption(w.S3ServerSideEncryption),
	}

	if _, err := svc.PutObject(context.TODO(), putObjectInput); err != nil {
		return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
			w.S3Bucket, path.Join(w.S3ResultsDir, k), err)
	}
	return nil
}
