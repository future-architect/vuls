// Package fvuls ...
package fvuls

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/saas"
	"github.com/future-architect/vuls/util"
)

// Client ...
type Client struct {
	Token             string
	Proxy             string
	FvulsScanEndpoint string
	FvulsRestEndpoint string
}

// NewClient ...
func NewClient(token string, proxy string) *Client {
	fvulsDomain := "vuls.biz"
	if domain := os.Getenv("VULS_DOMAIN"); 0 < len(domain) {
		fvulsDomain = domain
	}
	return &Client{
		Token:             token,
		Proxy:             proxy,
		FvulsScanEndpoint: fmt.Sprintf("https://auth.%s/one-time-auth", fvulsDomain),
		FvulsRestEndpoint: fmt.Sprintf("https://rest.%s/v1", fvulsDomain),
	}
}

// UploadToFvuls ...
func (f Client) UploadToFvuls(serverUUID string, groupID int64, tags []string, scanResultJSON []byte, timeout time.Duration) error {
	var scanResult models.ScanResult
	if err := json.Unmarshal(scanResultJSON, &scanResult); err != nil {
		fmt.Printf("failed to parse json. err: %v\nPerhaps scan has failed. Please check the scan results above or run trivy without pipes.\n", err)
		return err
	}
	for k, v := range scanResult.ScannedCves {
		if v.CveContents == nil {
			v.CveContents = models.NewCveContents()
			scanResult.ScannedCves[k] = v
		}
	}
	scanResult.ServerUUID = serverUUID
	if 0 < len(tags) {
		if scanResult.Optional == nil {
			scanResult.Optional = map[string]any{}
		}
		scanResult.Optional["VULS_TAGS"] = tags
	}

	w := saas.Writer{
		Cnf: config.SaasConf{
			GroupID: groupID,
			Token:   f.Token,
			URL:     f.FvulsScanEndpoint,
		},
		Timeout: timeout,
	}
	if err := w.Write(scanResult); err != nil {
		return fmt.Errorf("%v", err)
	}
	return nil
}

// GetServerByUUID ...
func (f Client) GetServerByUUID(ctx context.Context, uuid string) (server ServerDetailOutput, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/server/uuid/%s", f.FvulsRestEndpoint, uuid), nil)
	if err != nil {
		return ServerDetailOutput{}, fmt.Errorf("failed to create request. err: %v", err)
	}
	t, err := f.sendHTTPRequest(req)
	if err != nil {
		return ServerDetailOutput{}, err
	}
	var serverDetail ServerDetailOutput
	if err := json.Unmarshal(t, &serverDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return ServerDetailOutput{}, fmt.Errorf("invalid token")
		}
		return ServerDetailOutput{}, fmt.Errorf("failed to unmarshal serverDetail. err: %v", err)
	}
	return serverDetail, nil
}

// CreatePseudoServer ...
func (f Client) CreatePseudoServer(ctx context.Context, name string) (serverDetail ServerDetailOutput, err error) {
	payload := CreatePseudoServerInput{
		ServerName: name,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return ServerDetailOutput{}, fmt.Errorf("failed to Marshal to JSON: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/server/pseudo", f.FvulsRestEndpoint), bytes.NewBuffer(body))
	if err != nil {
		return ServerDetailOutput{}, fmt.Errorf("failed to create request: %v", err)
	}
	t, err := f.sendHTTPRequest(req)
	if err != nil {
		return ServerDetailOutput{}, err
	}
	if err := json.Unmarshal(t, &serverDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return ServerDetailOutput{}, fmt.Errorf("invalid token")
		}
		return ServerDetailOutput{}, fmt.Errorf("failed to unmarshal serverDetail. err: %v", err)
	}
	return serverDetail, nil
}

// UploadCPE ...
func (f Client) UploadCPE(ctx context.Context, cpeURI string, serverID int64) (err error) {
	payload := AddCpeInput{
		ServerID: serverID,
		CpeName:  cpeURI,
		IsURI:    false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/pkgCpe/cpe", f.FvulsRestEndpoint), bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create request. err: %v", err)
	}
	t, err := f.sendHTTPRequest(req)
	if err != nil {
		return err
	}
	var cpeDetail AddCpeOutput
	if err := json.Unmarshal(t, &cpeDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return fmt.Errorf("invalid token")
		}
		return fmt.Errorf("failed to unmarshal serverDetail. err: %v", err)
	}
	return nil
}

// ListUploadedCPE ...
func (f Client) ListUploadedCPE(ctx context.Context, serverID int64) (uploadedCPEs []string, err error) {
	page := 1
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/pkgCpes?page=%d&limit=%d&filterServerID=%d", f.FvulsRestEndpoint, page, 200, serverID), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request. err: %v", err)
		}
		t, err := f.sendHTTPRequest(req)
		if err != nil {
			return nil, err
		}
		var pkgCpes ListCpesOutput
		if err := json.Unmarshal(t, &pkgCpes); err != nil {
			if err.Error() == "invalid character 'A' looking for beginning of value" {
				return nil, fmt.Errorf("invalid token")
			}
			return nil, fmt.Errorf("failed to unmarshal listCpesOutput. err: %v", err)
		}
		for _, pkgCpe := range pkgCpes.PkgCpes {
			uploadedCPEs = append(uploadedCPEs, pkgCpe.CpeFS)
		}

		if pkgCpes.Paging.TotalPage <= page {
			break
		}
		page++
	}
	return uploadedCPEs, nil
}

func (f Client) sendHTTPRequest(req *http.Request) ([]byte, error) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", f.Token)
	client, err := util.GetHTTPClient(f.Proxy)
	if err != nil {
		return nil, fmt.Errorf("%v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to sent request. err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error response: %v", resp.StatusCode)
	}
	t, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response data. err: %v", err)
	}
	return t, nil
}
