package cpe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	"github.com/future-architect/vuls/util"
	"golang.org/x/exp/slices"
)

type createPseudoServerInput struct {
	ServerName string `json:"serverName"`
}

type createPseudoServerOutput struct {
	UUID string `json:"serverUuid"`
}

type addCpeInput struct {
	ServerID int64  `json:"serverID"`
	CpeName  string `json:"cpeName"`
	IsURI    bool   `json:"isURI"`
}

type addCpeOutput struct {
	Server serverChild `json:"server"`
}

type listCpesInput struct {
	Page     int   `json:"page"`
	Limit    int   `json:"limit"`
	ServerID int64 `json:"filterServerID"`
}

type listCpesOutput struct {
	Paging  paging    `json:"paging"`
	PkgCpes []pkgCpes `json:"pkgCpes"`
}

type paging struct {
	Page      int `json:"page"`
	Limit     int `json:"limit"`
	TotalPage int `json:"totalPage"`
}
type pkgCpes struct {
	CpeFS string `json:"cpeFS"`
}

type serverChild struct {
	ServerName string `json:"serverName"`
}

type getServerDetailByUUIDOutput struct {
	ServerID int64 `json:"id"`
}

func AddServerToFvuls(token string, outputFile string, proxy string, url string) error {
	var servers map[string]*schema.ServerDetail
	_, err := toml.DecodeFile(outputFile, &servers)
	if err != nil {
		return fmt.Errorf("failed to read %s", outputFile)
	}
	var notTargetHostCount int
	var createdHostCount int
	for _, params := range servers {
		if params.FvulsSync && params.UUID != "" {
			createdHostCount++
		} else if !params.FvulsSync {
			notTargetHostCount++
		}
	}
	if len(servers) == notTargetHostCount {
		return fmt.Errorf("there are no hosts with fvuls_sync set to true")
	}
	if len(servers)-notTargetHostCount == createdHostCount {
		fmt.Printf("All hosts already created as pseudo server. skip\n")
		return nil
	}

	fmt.Printf("Creating pseudo server...\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, params := range servers {
		if params.FvulsSync && params.UUID == "" {
			uuid, err := createPseudoServer(ctx, token, params.ServerName, proxy, url)
			if err != nil {
				fmt.Printf("%s: Failed to add to Fvuls server. err: %v\n", params.ServerName, err)
				continue
			}
			servers[params.IP].UUID = uuid
			fmt.Printf("%s: Created pseudo server %s\n", params.ServerName, params.ServerName)
		} else if params.FvulsSync && params.UUID != "" {
			fmt.Printf("%s: Pseudo server already created. skip\n", params.ServerName)
		}
	}

	f, err := os.OpenFile(outputFile, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("failed to open toml file. err: %v", err)
	}
	defer f.Close()
	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(servers); err != nil {
		return fmt.Errorf("failed to write to %s. err: %v", outputFile, err)
	}
	fmt.Printf("wrote to %s\n\n", outputFile)
	return nil
}

func createPseudoServer(ctx context.Context, token string, name string, proxy string, url string) (string, error) {
	payload := createPseudoServerInput{
		ServerName: name,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to Marshal to JSON: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/server/pseudo", url), bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	t, err := sendHTTPRequest(req, token, proxy)
	if err != nil {
		return "", err
	}
	var serverDetail createPseudoServerOutput
	if err := json.Unmarshal(t, &serverDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return "", fmt.Errorf("invalid token")
		}
		return "", fmt.Errorf("failed to unmarshal serverDetail. err: %v", err)
	}
	return serverDetail.UUID, nil
}

func AddCpeDataToFvuls(token string, outputFile string, proxy string, url string) error {
	var servers map[string]*schema.ServerDetail
	_, err := toml.DecodeFile(outputFile, &servers)
	if err != nil {
		return fmt.Errorf("failed to read %s", outputFile)
	}
	var targetServerCount int
	for _, params := range servers {
		if params.CpeURI != nil && params.UUID != "" {
			targetServerCount++
		}
	}
	if targetServerCount == 0 {
		return fmt.Errorf("cpe upload target not found")
	}

	fmt.Printf("Uploading CPE...\n")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for addr, params := range servers {
		if params.UUID != "" && params.CpeURI != nil {
			if len(params.CpeURI) == 0 {
				fmt.Printf("%s: There is no cpe_uri to upload. skip\n", params.ServerName)
				continue
			}
			serverID, err := fetchServerIDByUUID(ctx, params.UUID, token, proxy, url)
			if err != nil {
				fmt.Printf("%s: Failed to Fetch serverID. err: %v\n", params.ServerName, err)
				continue
			}
			var uploadedCpes []string
			var allUploadedCpes []string
			var page int
			var isAllFetched bool
			for {
				page++
				uploadedCpes, isAllFetched, err = fetchUploadedCPEData(ctx, token, proxy, listCpesInput{
					Page:     page,
					Limit:    10,
					ServerID: serverID,
				}, url)
				if err != nil {
					fmt.Printf("%s: Failed to Fetch uploaded cpes. err: %v\n", params.ServerName, err)
					break
				}
				allUploadedCpes = append(allUploadedCpes, uploadedCpes...)
				if isAllFetched {
					break
				}
			}
			uploadSuccessCount := 0
			var serverName string
			var correctServerName string
			for _, Cpe := range params.CpeURI {
				if slices.Contains(allUploadedCpes, Cpe) {
					fmt.Printf("%s: %s already added. skip\n", params.ServerName, Cpe)
					continue
				} else {

					if serverName, err = uploadCPEData(ctx, Cpe, serverID, token, proxy, url); err != nil {
						fmt.Printf("%s: Failed to upload CPE %s. err: %v\n", params.ServerName, Cpe, err)
						continue
					}
					fmt.Printf("%s: Uploaded CPE %s\n", params.ServerName, Cpe)
					if serverName != "" && serverName != servers[addr].ServerName {
						correctServerName = serverName
					}
					uploadSuccessCount++
				}
			}
			if correctServerName != "" {
				servers[addr].ServerName = correctServerName
				fmt.Printf("%s: Changed server_name in toml file to %s because the server name is different from the registered one\n", params.ServerName, correctServerName)
			}
			fmt.Printf("%s: Uploaded %d of the %d cpes to Fvuls.\n", params.ServerName, uploadSuccessCount, len(params.CpeURI))
		}
	}
	return nil
}

func fetchServerIDByUUID(ctx context.Context, uuid string, token string, proxy string, url string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/server/uuid/%s", url, uuid), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request. err: %v", err)
	}
	t, err := sendHTTPRequest(req, token, proxy)
	if err != nil {
		return 0, err
	}
	var serverDetail getServerDetailByUUIDOutput
	if err := json.Unmarshal(t, &serverDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return 0, fmt.Errorf("invalid token")
		}
		return 0, fmt.Errorf("failed to unmarshal serverDetail. err: %v", err)
	}
	return serverDetail.ServerID, nil
}

func fetchUploadedCPEData(ctx context.Context, token string, proxy string, listCpeOption listCpesInput, url string) ([]string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/pkgCpes?page=%d&limit=%d&filterServerID=%d", url, listCpeOption.Page, listCpeOption.Limit, listCpeOption.ServerID), nil)
	if err != nil {
		return nil, false, fmt.Errorf("failed to create request. err: %v", err)
	}
	t, err := sendHTTPRequest(req, token, proxy)
	if err != nil {
		return nil, false, err
	}
	var pkgCpes listCpesOutput
	if err := json.Unmarshal(t, &pkgCpes); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return nil, false, fmt.Errorf("invalid token")
		}
		return nil, false, fmt.Errorf("failed to unmarshal listCpesOutput. err: %v", err)
	}
	var uploadedCpes []string
	for _, pkgCpe := range pkgCpes.PkgCpes {
		uploadedCpes = append(uploadedCpes, pkgCpe.CpeFS)
	}
	if pkgCpes.Paging.Page == pkgCpes.Paging.TotalPage || pkgCpes.Paging.TotalPage == 0 {
		return uploadedCpes, true, nil
	}
	return uploadedCpes, false, nil
}

func uploadCPEData(ctx context.Context, cpe string, serverID int64, token string, proxy string, url string) (string, error) {
	payload := addCpeInput{
		ServerID: serverID,
		CpeName:  cpe,
		IsURI:    false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/pkgCpe/cpe", url), bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request. err: %v", err)
	}
	t, err := sendHTTPRequest(req, token, proxy)
	if err != nil {
		return "", err
	}
	var cpeDetail addCpeOutput
	if err := json.Unmarshal(t, &cpeDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return "", fmt.Errorf("invalid token")
		}
		return "", fmt.Errorf("failed to unmarshal serverDetail. err: %v", err)
	}
	return cpeDetail.Server.ServerName, nil
}

func sendHTTPRequest(req *http.Request, token string, proxy string) ([]byte, error) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)
	client, err := util.GetHTTPClient(proxy)
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
