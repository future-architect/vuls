/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// CheckIfBucketExists check the existence of S3 bucket
func CheckIfBucketExists() error {
	svc := getS3()
	result, err := svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf(
			"Failed to list buckets. err: %s, profile: %s, region: %s",
			err, c.Conf.AwsProfile, c.Conf.AwsRegion)
	}

	found := false
	for _, bucket := range result.Buckets {
		if *bucket.Name == c.Conf.S3Bucket {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf(
			"Failed to find the buckets. profile: %s, region: %s, bukdet: %s",
			c.Conf.AwsProfile, c.Conf.AwsRegion, c.Conf.S3Bucket)
	}
	return nil
}

// S3Writer writes results to S3
type S3Writer struct{}

func getS3() *s3.S3 {
	return s3.New(session.New(&aws.Config{
		Region:      aws.String(c.Conf.AwsRegion),
		Credentials: credentials.NewSharedCredentials("", c.Conf.AwsProfile),
	}))
}

// Write results to S3
func (w S3Writer) Write(scanResults []models.ScanResult) (err error) {

	var jsonBytes []byte
	if jsonBytes, err = json.Marshal(scanResults); err != nil {
		return fmt.Errorf("Failed to Marshal to JSON: %s", err)
	}

	// http://docs.aws.amazon.com/sdk-for-go/latest/v1/developerguide/common-examples.title.html
	svc := getS3()
	timestr := time.Now().Format("20060102_1504")
	key := fmt.Sprintf("%s/%s", timestr, "all.json")
	_, err = svc.PutObject(&s3.PutObjectInput{
		Bucket: &c.Conf.S3Bucket,
		Key:    &key,
		Body:   bytes.NewReader(jsonBytes),
	})
	if err != nil {
		return fmt.Errorf("Failed to upload data to %s/%s, %s", c.Conf.S3Bucket, key, err)
	}

	for _, r := range scanResults {
		key := ""
		if len(r.Container.ContainerID) == 0 {
			key = fmt.Sprintf("%s/%s.json", timestr, r.ServerName)
		} else {
			key = fmt.Sprintf("%s/%s_%s.json", timestr, r.ServerName, r.Container.Name)
		}

		if jsonBytes, err = json.Marshal(r); err != nil {
			return fmt.Errorf("Failed to Marshal to JSON: %s", err)
		}
		_, err = svc.PutObject(&s3.PutObjectInput{
			Bucket: &c.Conf.S3Bucket,
			Key:    &key,
			Body:   bytes.NewReader(jsonBytes),
		})
		if err != nil {
			return fmt.Errorf("Failed to upload data to %s/%s, %s", c.Conf.S3Bucket, key, err)
		}
	}
	return nil
}
