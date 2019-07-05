/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// SaasWriter writes results to SaaS
type SaasWriter struct{}

// TempCredential : TempCredential
type TempCredential struct {
	Credential   *sts.Credentials `json:"Credential"`
	S3Bucket     string           `json:"S3Bucket"`
	S3ResultsDir string           `json:"S3ResultsDir"`
}

type payload struct {
	GroupID      int    `json:"GroupID"`
	Token        string `json:"Token"`
	ScannedBy    string `json:"ScannedBy"`
	ScannedIPv4s string `json:"ScannedIPv4s"`
	ScannedIPv6s string `json:"ScannedIPv6s"`
}

// UploadSaas : UploadSaas
func (w SaasWriter) Write(rs ...models.ScanResult) (err error) {
	// dir string, configPath string, config *c.Config
	if len(rs) == 0 {
		return nil
	}

	ipv4s, ipv6s, err := util.IP()
	if err != nil {
		util.Log.Errorf("Failed to fetch scannedIPs. err: %+v", err)
	}
	hostname, _ := os.Hostname()

	payload := payload{
		GroupID:      c.Conf.Saas.GroupID,
		Token:        c.Conf.Saas.Token,
		ScannedBy:    hostname,
		ScannedIPv4s: strings.Join(ipv4s, ", "),
		ScannedIPv6s: strings.Join(ipv6s, ", "),
	}

	var body []byte
	if body, err = json.Marshal(payload); err != nil {
		return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
	}

	var req *http.Request
	if req, err = http.NewRequest("POST", c.Conf.Saas.URL, bytes.NewBuffer(body)); err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	proxy := c.Conf.HTTPProxy
	var client http.Client
	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		client = http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			},
		}
	} else {
		client = http.Client{}
	}

	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return xerrors.Errorf("Failed to get Credential. Request JSON : %s,", string(body))
	}

	var t []byte
	if t, err = ioutil.ReadAll(resp.Body); err != nil {
		return err
	}

	var tempCredential TempCredential
	if err = json.Unmarshal(t, &tempCredential); err != nil {
		return xerrors.Errorf("Failed to unmarshal saas credential file. err : %s", err)
	}

	credential := credentials.NewStaticCredentialsFromCreds(credentials.Value{
		AccessKeyID:     *tempCredential.Credential.AccessKeyId,
		SecretAccessKey: *tempCredential.Credential.SecretAccessKey,
		SessionToken:    *tempCredential.Credential.SessionToken,
	})

	var sess *session.Session
	if sess, err = session.NewSession(&aws.Config{
		Credentials: credential,
		Region:      aws.String("ap-northeast-1"),
	}); err != nil {
		return xerrors.Errorf("Failed to new aws session. err: %w", err)
	}

	svc := s3.New(sess)
	for _, r := range rs {
		s3Key := renameKeyNameUTC(r.ScannedAt, r.ServerUUID, r.Container)
		var b []byte
		if b, err = json.Marshal(r); err != nil {
			return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
		}
		util.Log.Infof("Uploading...: ServerName: %s, ", r.ServerName)
		putObjectInput := &s3.PutObjectInput{
			Bucket: aws.String(tempCredential.S3Bucket),
			Key:    aws.String(path.Join(tempCredential.S3ResultsDir, s3Key)),
			Body:   bytes.NewReader(b),
		}

		if _, err := svc.PutObject(putObjectInput); err != nil {
			return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
				tempCredential.S3Bucket, s3Key, err)
		}
	}
	util.Log.Infof("done")
	return nil
}

func renameKeyNameUTC(scannedAt time.Time, uuid string, container models.Container) string {
	timestr := scannedAt.UTC().Format(time.RFC3339)
	if len(container.ContainerID) == 0 {
		return fmt.Sprintf("%s/%s.json", timestr, uuid)
	}
	return fmt.Sprintf("%s/%s@%s.json", timestr, container.UUID, uuid)
}
