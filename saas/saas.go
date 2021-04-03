package saas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"golang.org/x/xerrors"
)

// Writer writes results to SaaS
type Writer struct{}

// TempCredential : TempCredential
type TempCredential struct {
	Credential   *sts.Credentials `json:"Credential"`
	S3Bucket     string           `json:"S3Bucket"`
	S3ResultsDir string           `json:"S3ResultsDir"`
}

type payload struct {
	GroupID      int64  `json:"GroupID"`
	Token        string `json:"Token"`
	ScannedBy    string `json:"ScannedBy"`
	ScannedIPv4s string `json:"ScannedIPv4s"`
	ScannedIPv6s string `json:"ScannedIPv6s"`
}

// UploadSaas : UploadSaas
func (w Writer) Write(rs ...models.ScanResult) error {
	if len(rs) == 0 {
		return nil
	}

	ipv4s, ipv6s, err := util.IP()
	if err != nil {
		logging.Log.Warnf("Failed to get scannedIPs. err: %+v", err)
	}
	hostname, _ := os.Hostname()

	payload := payload{
		GroupID:      config.Conf.Saas.GroupID,
		Token:        config.Conf.Saas.Token,
		ScannedBy:    hostname,
		ScannedIPv4s: strings.Join(ipv4s, ", "),
		ScannedIPv6s: strings.Join(ipv6s, ", "),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, config.Conf.Saas.URL, bytes.NewBuffer(body))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	// TODO Don't use global variable
	client, err := util.GetHTTPClient(config.Conf.HTTPProxy)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return xerrors.Errorf("Failed to get Credential. Request JSON : %s,", string(body))
	}

	t, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var tempCredential TempCredential
	if err := json.Unmarshal(t, &tempCredential); err != nil {
		return xerrors.Errorf("Failed to unmarshal saas credential file. err : %s", err)
	}

	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentialsFromCreds(credentials.Value{
			AccessKeyID:     *tempCredential.Credential.AccessKeyId,
			SecretAccessKey: *tempCredential.Credential.SecretAccessKey,
			SessionToken:    *tempCredential.Credential.SessionToken,
		}),
		Region: aws.String("ap-northeast-1"),
	})
	if err != nil {
		return xerrors.Errorf("Failed to new aws session. err: %w", err)
	}

	svc := s3.New(sess)
	for _, r := range rs {
		b, err := json.Marshal(r)
		if err != nil {
			return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
		}
		logging.Log.Infof("Uploading... %s", r.FormatServerName())
		s3Key := renameKeyName(r.ServerUUID, r.Container)
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
	logging.Log.Infof("done")
	return nil
}

func renameKeyName(uuid string, container models.Container) string {
	if len(container.ContainerID) == 0 {
		return fmt.Sprintf("%s.json", uuid)
	}
	return fmt.Sprintf("%s@%s.json", container.UUID, uuid)
}
