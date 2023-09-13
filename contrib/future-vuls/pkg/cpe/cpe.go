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
)

type addCpeInput struct {
	ServerID int64  `json:"serverID"`
	CpeName  string `json:"cpeName"`
	IsURI    bool   `json:"isURI"`
}

type addCpeOutput struct {
	Server serverChild `json:"server"`
}

type serverChild struct {
	ServerName string `json:"serverName"`
}

type getServerDetailByUUIDOutput struct {
	ServerID int64 `json:"id"`
}

// AddCpeDataToFvuls ...
func AddCpeDataToFvuls(token string, outputFile string, proxy string) error {
	var servers map[string]*schema.ServerDetail
	_, err := toml.DecodeFile(outputFile, &servers)
	if err != nil {
		return fmt.Errorf("failed to read %s", outputFile)
	}

	targetServerCount := 0
	//This flag indicates whether at least one cpe has been added
	isAnyCpeAdded := false
	fmt.Printf("Uploading CPE...  URL: %s/pkgCpe/cpe\n", schema.RestEndPoint)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for addr, params := range servers {
		if params.FvulsSync && params.UUID != "" && params.CpeURI != nil {
			targetServerCount++

			serverID, err := fetchServerIDByUUID(ctx, params.UUID, token, proxy)
			if err != nil {
				fmt.Printf("%s: Failed to Fetch serverID. err: %v\n", params.ServerName, err)
				continue
			}
			uploadedCpeCount := 0
			fmt.Printf("%s: Upload CPE...\n", params.ServerName)
			var serverName string
			var correctServerName string
			for _, Cpe := range params.CpeURI {
				if serverName, err = uploadCPEData(ctx, Cpe, serverID, token, proxy); err != nil {
					fmt.Printf("%s: Failed to upload CPE %s. err: %v\n", params.ServerName, Cpe, err)
					continue
				}
				fmt.Printf("%s: Uploaded CPE %s\n", params.ServerName, Cpe)
				if serverName != "" && serverName != servers[addr].ServerName {
					correctServerName = serverName
				}
				isAnyCpeAdded = true
				uploadedCpeCount++
			}
			if correctServerName != "" {
				servers[addr].ServerName = correctServerName
				fmt.Printf("%s: Changed server_name in toml file to %s because the server name is different from the registered one\n", params.ServerName, correctServerName)
			}
			fmt.Printf("%s: Done.\n", params.ServerName)
			fmt.Printf("%s: Uploaded %d of the %d cpes to Fvuls.\n", params.ServerName, uploadedCpeCount, len(params.CpeURI))
		}
	}
	if targetServerCount == 0 {
		return fmt.Errorf("upload target not found error")
	}
	if !isAnyCpeAdded {
		return fmt.Errorf("cpe upload failed for all servers")
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
	fmt.Printf("Successfully wrote to %s\n", outputFile)
	return nil
}

func fetchServerIDByUUID(ctx context.Context, uuid string, token string, proxy string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/server/uuid/%s", schema.RestEndPoint, uuid), nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request. err: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)
	client, err := util.GetHTTPClient(proxy)
	if err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to sent request. err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("failed to get serverId. err: %v", resp.StatusCode)
	}
	t, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response data. err: %v", err)
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

func uploadCPEData(ctx context.Context, cpe string, serverID int64, token string, proxy string) (string, error) {
	payload := addCpeInput{
		ServerID: serverID,
		CpeName:  cpe,
		IsURI:    false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal JSON: %v", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/pkgCpe/cpe", schema.RestEndPoint), bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("failed to create request. err: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)

	client, err := util.GetHTTPClient(proxy)
	if err != nil {
		return "", fmt.Errorf("%v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to sent request. err: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("failed to add cpe. err: %v", resp.StatusCode)
	}
	t, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response data. err: %v", err)
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
