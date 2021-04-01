package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
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

func (w S3Writer) getS3() (*s3.S3, error) {
	ses, err := session.NewSession()
	if err != nil {
		return nil, err
	}
	config := &aws.Config{
		Region: aws.String(w.Region),
		Credentials: credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{Filename: "", Profile: w.Profile},
			&ec2rolecreds.EC2RoleProvider{Client: ec2metadata.New(ses)},
		}),
	}
	s, err := session.NewSession(config)
	if err != nil {
		return nil, err
	}
	return s3.New(s), nil
}

// Write results to S3
// http://docs.aws.amazon.com/sdk-for-go/latest/v1/developerguide/common-examples.title.html
func (w S3Writer) Write(rs ...models.ScanResult) (err error) {
	if len(rs) == 0 {
		return nil
	}

	svc, err := w.getS3()
	if err != nil {
		return err
	}

	if w.FormatOneLineText {
		timestr := rs[0].ScannedAt.Format(time.RFC3339)
		k := fmt.Sprintf(timestr + "/summary.txt")
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

// Validate check the existence of S3 bucket
func (w S3Writer) Validate() error {
	svc, err := w.getS3()
	if err != nil {
		return err
	}

	result, err := svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return xerrors.Errorf("Failed to list buckets. err: %w, profile: %s, region: %s",
			err, w.Profile, w.Region)
	}

	found := false
	for _, bucket := range result.Buckets {
		if *bucket.Name == w.S3Bucket {
			found = true
			break
		}
	}
	if !found {
		return xerrors.Errorf("Failed to find the buckets. profile: %s, region: %s, bucket: %s",
			w.Profile, w.Region, w.S3Bucket)
	}
	return nil
}

func (w S3Writer) putObject(svc *s3.S3, k string, b []byte, gzip bool) error {
	var err error
	if gzip {
		if b, err = gz(b); err != nil {
			return err
		}
		k += ".gz"
	}

	putObjectInput := &s3.PutObjectInput{
		Bucket: aws.String(w.S3Bucket),
		Key:    aws.String(path.Join(w.S3ResultsDir, k)),
		Body:   bytes.NewReader(b),
	}

	if w.S3ServerSideEncryption != "" {
		putObjectInput.ServerSideEncryption = aws.String(w.S3ServerSideEncryption)
	}

	if _, err := svc.PutObject(putObjectInput); err != nil {
		return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
			w.S3Bucket, k, err)
	}
	return nil
}
