package cpe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	"github.com/future-architect/vuls/util"
	"golang.org/x/exp/slices"
)

type AddCpeInput struct {
	ServerID int64  `json:"serverID"`
	CpeName  string `json:"cpeName"`
	IsURI    bool   `json:"isURI"`
}

type GetServerDetailByUUIDOutput struct {
	ServerID int64 `json:"id"`
}

func AddCpeDataToFvuls(url string, token string, snmpVersion string, outputFile string) error {
	var servers map[string]*schema.ServerDetail
	_, err := toml.DecodeFile(outputFile, &servers)
	if err != nil {
		return fmt.Errorf("Failed to read %s\n", outputFile)
	}

	targetServerCount := 0
	//This flag indicates whether at least one cpe has been added
	isAnyCpeAdded := false
	fmt.Printf("Uploading CPE to %s/pkgCpe/cpe...\n", url)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for addr, params := range servers {
		if params.FvulsSync && params.UUID != "" {
			targetServerCount++
			jsonData, err := ExecuteSnmp2cpe(addr, snmpVersion)
			if err != nil {
				fmt.Printf("%s: Failed to execute snmp2cpe. err: %v\n", addr, err)
				continue
			}
			fmt.Printf("%s: Done.\n", addr)
			var newCpes []string
			for _, cpe := range jsonData[addr] {
				if !slices.Contains(params.CpeURI, cpe) {
					fmt.Printf("%s: Found new cpe: %s\n", addr, cpe)
					newCpes = append(newCpes, cpe)
				}
			}

			serverID, err := FetchServerIDByUUID(ctx, params.UUID, url, token)
			if err != nil {
				fmt.Printf("%s: Failed to Fetch serverID. err: %v\n", addr, err)
				continue
			}
			uploadedCpeCount := 0
			fmt.Printf("%s: Upload CPE...\n", addr)
			if len(newCpes) == 0 {
				fmt.Printf("%s: New CPE datas not found.\n", addr)
			}
			for _, newCpe := range newCpes {
				if err := UploadCPEData(ctx, newCpe, serverID, url, token); err != nil {
					fmt.Printf("%s: Failed to upload CPE %s. err: %v\n", addr, newCpe, err)
					continue
				}
				servers[params.IP].CpeURI = append(servers[params.IP].CpeURI, newCpe)
				isAnyCpeAdded = true
				uploadedCpeCount++
			}
			fmt.Printf("%s: Done.\n", addr)
			fmt.Printf("%s: Successfully uploaded %d cpes to Fvuls.\n\n", addr, uploadedCpeCount)
		}
	}
	if targetServerCount == 0 {
		fmt.Printf("The target of the command could not be found, please rewrite the FvulsSync to true and execute future-vuls add-server command to fetch UUID.\n")
		return fmt.Errorf("command target not found error\n")
	}
	if !isAnyCpeAdded {
		return fmt.Errorf("CPE upload failed for all servers.\n")
	}

	f, err := os.OpenFile(outputFile, os.O_RDWR, 0666)
	if err != nil {
		return fmt.Errorf("Failed to open toml file. err: %v\n", err)
	}
	defer f.Close()
	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(servers); err != nil {
		return fmt.Errorf("Failed to write to %s. err: %v\n", outputFile, err)
	}
	fmt.Printf("Successfully wrote to %s\n", outputFile)
	return nil
}

func ExecuteSnmp2cpe(addr string, snmpVersion string) (map[string][]string, error) {
	fmt.Printf("%s: Execute snmp2cpe...\n", addr)
	result, err := exec.Command("./snmp2cpe", snmpVersion, addr, "public").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Failed to execute snmp2cpe. err: %v\n", err)
	}
	cmd := exec.Command("./snmp2cpe", "convert")
	stdin, err := cmd.StdinPipe()
	io.WriteString(stdin, string(result))
	stdin.Close()
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Failed to convert snmp2cpe result. err: %v\n", err)
	}

	var jsonData map[string][]string
	if err := json.Unmarshal(output, &jsonData); err != nil {
		return nil, fmt.Errorf("Failed to unmarshal snmp2cpe output. err: %v\n", err)
	}
	return jsonData, nil
}

func FetchServerIDByUUID(ctx context.Context, uuid string, url string, token string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/server/uuid/%s", url, uuid), nil)
	if err != nil {
		return 0, fmt.Errorf("Failed to create request. err: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)
	client, err := util.GetHTTPClient(config.Conf.HTTPProxy)
	if err != nil {
		return 0, fmt.Errorf("%v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("Failed to sent request. err: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("Failed to get serverId. err: %v\n", resp.StatusCode)
	}
	t, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("Failed to read response data. err: %v\n", err)
	}

	var serverDetail GetServerDetailByUUIDOutput
	if err := json.Unmarshal(t, &serverDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return 0, fmt.Errorf("Invalid token")
		}
		return 0, fmt.Errorf("Failed to unmarshal serverDetail. err: %v\n", err)
	}
	return serverDetail.ServerID, nil
}

func UploadCPEData(ctx context.Context, cpe string, serverID int64, url string, token string) error {
	payload := AddCpeInput{
		ServerID: serverID,
		CpeName:  cpe,
		IsURI:    false,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("Failed to marshal JSON: %v\n", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/pkgCpe/cpe", url), bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("Failed to create request. err: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)

	client, err := util.GetHTTPClient(config.Conf.HTTPProxy)
	if err != nil {
		return fmt.Errorf("%v\n", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Failed to sent request. err: %v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Failed to add cpe. err: %v\n", resp.StatusCode)
	}
	return nil
}
