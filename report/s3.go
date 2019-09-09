package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
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

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// S3Writer writes results to S3
type S3Writer struct{}

func getS3() *s3.S3 {
	Config := &aws.Config{
		Region: aws.String(c.Conf.AWS.Region),
		Credentials: credentials.NewChainCredentials([]credentials.Provider{
			&credentials.EnvProvider{},
			&credentials.SharedCredentialsProvider{Filename: "", Profile: c.Conf.AWS.Profile},
			&ec2rolecreds.EC2RoleProvider{Client: ec2metadata.New(session.New())},
		}),
	}
	return s3.New(session.New(Config))
}

// Write results to S3
// http://docs.aws.amazon.com/sdk-for-go/latest/v1/developerguide/common-examples.title.html
func (w S3Writer) Write(rs ...models.ScanResult) (err error) {
	if len(rs) == 0 {
		return nil
	}

	svc := getS3()

	if c.Conf.FormatOneLineText {
		timestr := rs[0].ScannedAt.Format(time.RFC3339)
		k := fmt.Sprintf(timestr + "/summary.txt")
		text := formatOneLineSummary(rs...)
		if err := putObject(svc, k, []byte(text)); err != nil {
			return err
		}
	}

	for _, r := range rs {
		key := r.ReportKeyName()
		if c.Conf.FormatJSON {
			k := key + ".json"
			var b []byte
			if b, err = json.Marshal(r); err != nil {
				return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
			}
			if err := putObject(svc, k, b); err != nil {
				return err
			}
		}

		if c.Conf.FormatList {
			k := key + "_short.txt"
			text := formatList(r)
			if err := putObject(svc, k, []byte(text)); err != nil {
				return err
			}
		}

		if c.Conf.FormatFullText {
			k := key + "_full.txt"
			text := formatFullPlainText(r)
			if err := putObject(svc, k, []byte(text)); err != nil {
				return err
			}
		}

		if c.Conf.FormatXML {
			k := key + ".xml"
			var b []byte
			if b, err = xml.Marshal(r); err != nil {
				return xerrors.Errorf("Failed to Marshal to XML: %w", err)
			}
			allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), b, []byte(vulsCloseTag)}, []byte{})
			if err := putObject(svc, k, allBytes); err != nil {
				return err
			}
		}
	}
	return nil
}

// CheckIfBucketExists check the existence of S3 bucket
func CheckIfBucketExists() error {
	svc := getS3()
	result, err := svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return xerrors.Errorf(
			"Failed to list buckets. err: %w, profile: %s, region: %s",
			err, c.Conf.AWS.Profile, c.Conf.AWS.Region)
	}

	found := false
	for _, bucket := range result.Buckets {
		if *bucket.Name == c.Conf.AWS.S3Bucket {
			found = true
			break
		}
	}
	if !found {
		return xerrors.Errorf(
			"Failed to find the buckets. profile: %s, region: %s, bucket: %s",
			c.Conf.AWS.Profile, c.Conf.AWS.Region, c.Conf.AWS.S3Bucket)
	}
	return nil
}

func putObject(svc *s3.S3, k string, b []byte) error {
	var err error
	if c.Conf.GZIP {
		if b, err = gz(b); err != nil {
			return err
		}
		k += ".gz"
	}

	putObjectInput := &s3.PutObjectInput{
		Bucket: aws.String(c.Conf.AWS.S3Bucket),
		Key:    aws.String(path.Join(c.Conf.AWS.S3ResultsDir, k)),
		Body:   bytes.NewReader(b),
	}

	if c.Conf.AWS.S3ServerSideEncryption != "" {
		putObjectInput.ServerSideEncryption = aws.String(c.Conf.AWS.S3ServerSideEncryption)
	}

	if _, err := svc.PutObject(putObjectInput); err != nil {
		return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
			c.Conf.AWS.S3Bucket, k, err)
	}
	return nil
}
