package server

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
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	"github.com/future-architect/vuls/util"
)

type CreatePseudoServerInput struct {
	APIKey     string `json:"api_key"`
	ServerName string `json:"serverName"`
}

type CreatePseudoServerOutput struct {
	UUID string `json:"serverUuid"`
}

func AddServerToFvuls(url string, token string, outputFile string) error {
	var servers map[string]*schema.ServerDetail
	_, err := toml.DecodeFile(outputFile, &servers)
	if err != nil {
		return fmt.Errorf("Failed to read %s\n", outputFile)
	}

	targetServerCount := 0
	//This flag indicates whether at least one server has been added
	isAnyServerAdded := false
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for addr, params := range servers {
		if params.FvulsSync && params.UUID == "" {
			fmt.Printf("%v: Adding to Fvuls server...\n", addr)
			targetServerCount++
			uuid, err := CreatePseudoServer(ctx, url, token, addr)
			if err != nil {
				fmt.Printf("%s: Failed to add to Fvuls server. err: %v\n", addr, err)
				continue
			}
			servers[addr].UUID = uuid
			fmt.Printf("%s: Done.\n", addr)
			isAnyServerAdded = true
		}
	}
	if targetServerCount == 0 {
		fmt.Printf("The target of the command could not be found, please rewrite the FvulsSync to true.\n")
		return fmt.Errorf("Command target not found error\n")
	}
	if !isAnyServerAdded {
		return fmt.Errorf("All server uploads failed\n")
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

func CreatePseudoServer(ctx context.Context, url string, token string, addr string) (string, error) {
	payload := CreatePseudoServerInput{
		ServerName: addr,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("Failed to Marshal to JSON: %v\n", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/server/pseudo", url), bytes.NewBuffer(body))
	if err != nil {
		return "", fmt.Errorf("Failed to create request: %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", token)

	client, err := util.GetHTTPClient(config.Conf.HTTPProxy)
	if err != nil {
		return "", fmt.Errorf("%v\n", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%v\n", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Falied to create pseudo server. statusCode: %d\n", resp.StatusCode)
	}
	t, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Failed to read response data. err: %v\n", err)
	}
	var serverDetail CreatePseudoServerOutput
	if err := json.Unmarshal(t, &serverDetail); err != nil {
		if err.Error() == "invalid character 'A' looking for beginning of value" {
			return "", fmt.Errorf("Invalid token")
		}
		return "", fmt.Errorf("Failed to unmarshal serverDetail. err: %v\n", err)
	}
	return serverDetail.UUID, nil
}
