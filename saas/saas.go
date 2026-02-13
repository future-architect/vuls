package saas

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// Writer writes results to SaaS
type Writer struct {
	Cnf     config.SaasConf
	Proxy   string
	Timeout time.Duration
}

// TempCredential : TempCredential
type TempCredential struct {
	Credential   *types.Credentials `json:"Credential"`
	S3Bucket     string             `json:"S3Bucket"`
	S3ResultsDir string             `json:"S3ResultsDir"`
}

type payload struct {
	GroupID      int64  `json:"GroupID"`
	Token        string `json:"Token"`
	ScannedBy    string `json:"ScannedBy"`
	ScannedIPv4s string `json:"ScannedIPv4s"`
	ScannedIPv6s string `json:"ScannedIPv6s"`
}

// Write :
func (w Writer) Write(rs ...models.ScanResult) error {
	if len(rs) == 0 {
		return nil
	}
	tags := strings.Split(os.Getenv("VULS_TAGS"), ",")

	ipv4s, ipv6s, err := util.IP()
	if err != nil {
		logging.Log.Warnf("Failed to get scannedIPs. err: %+v", err)
	}
	hostname, _ := os.Hostname()

	payload := payload{
		GroupID:      w.Cnf.GroupID,
		Token:        w.Cnf.Token,
		ScannedBy:    hostname,
		ScannedIPv4s: strings.Join(ipv4s, ", "),
		ScannedIPv6s: strings.Join(ipv6s, ", "),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return xerrors.Errorf("Failed to Marshal to JSON: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), w.Timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.Cnf.URL, bytes.NewBuffer(body))
	defer cancel()
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client, err := util.GetHTTPClient(w.Proxy)
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

	t, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var tempCredential TempCredential
	if err := json.Unmarshal(t, &tempCredential); err != nil {
		return xerrors.Errorf("Failed to unmarshal saas credential file. err : %s", err)
	}

	cfg, err := awsConfig.LoadDefaultConfig(ctx,
		awsConfig.WithRegion("ap-northeast-1"),
		awsConfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(*tempCredential.Credential.AccessKeyId, *tempCredential.Credential.SecretAccessKey, *tempCredential.Credential.SessionToken)),
	)
	if err != nil {
		return xerrors.Errorf("Failed to load config. err: %w", err)
	}
	// For S3 upload of aws sdk
	if err := os.Setenv("HTTPS_PROXY", w.Proxy); err != nil {
		return xerrors.Errorf("Failed to set HTTP proxy: %s", err)
	}

	svc := s3.NewFromConfig(cfg)
	for _, r := range rs {
		if 0 < len(tags) {
			if r.Optional == nil {
				r.Optional = map[string]any{}
			}
			r.Optional["VULS_TAGS"] = tags
		}

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
		if _, err := svc.PutObject(ctx, putObjectInput); err != nil {
			return xerrors.Errorf("Failed to upload data to %s/%s, err: %w",
				tempCredential.S3Bucket, path.Join(tempCredential.S3ResultsDir, s3Key), err)
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
