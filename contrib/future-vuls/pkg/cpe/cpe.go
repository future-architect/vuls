// Package cpe ...
package cpe

import (
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/future-architect/vuls/contrib/future-vuls/pkg/config"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/fvuls"
)

// AddCpeConfig ...
type AddCpeConfig struct {
	Token                string
	Proxy                string
	DiscoverTomlPath     string
	OriginalDiscoverToml config.DiscoverToml
}

// AddCpe ...
func AddCpe(token, outputFile, proxy string) (err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cpeConfig := &AddCpeConfig{
		Token:            token,
		Proxy:            proxy,
		DiscoverTomlPath: outputFile,
	}

	var needAddServers, needAddCpes config.DiscoverToml
	if needAddServers, needAddCpes, err = cpeConfig.LoadAndCheckTomlFile(ctx); err != nil {
		return err
	}

	if 0 < len(needAddServers) {
		addedServers := cpeConfig.AddServerToFvuls(ctx, needAddServers)
		if 0 < len(addedServers) {
			maps.Copy(needAddCpes, addedServers)
		}

		// update discover toml
		maps.Copy(cpeConfig.OriginalDiscoverToml, needAddCpes)
		if err = cpeConfig.WriteDiscoverToml(); err != nil {
			return err
		}
	}

	if 0 < len(needAddCpes) {
		var addedCpes config.DiscoverToml
		if addedCpes, err = cpeConfig.AddCpeToFvuls(ctx, needAddCpes); err != nil {
			return err
		}
		maps.Copy(cpeConfig.OriginalDiscoverToml, addedCpes)
		if err = cpeConfig.WriteDiscoverToml(); err != nil {
			return err
		}
	}
	return nil
}

// LoadAndCheckTomlFile ...
func (c *AddCpeConfig) LoadAndCheckTomlFile(ctx context.Context) (needAddServers, needAddCpes config.DiscoverToml, err error) {
	var discoverToml config.DiscoverToml
	if _, err = toml.DecodeFile(c.DiscoverTomlPath, &discoverToml); err != nil {
		return nil, nil, fmt.Errorf("failed to read discover toml: %s, err: %v", c.DiscoverTomlPath, err)
	}
	c.OriginalDiscoverToml = discoverToml

	needAddServers = make(map[string]config.ServerSetting)
	needAddCpes = make(map[string]config.ServerSetting)
	for name, setting := range discoverToml {
		if !setting.FvulsSync {
			continue
		}

		if setting.UUID == "" {
			setting.NewCpeURIs = setting.CpeURIs
			needAddServers[name] = setting
		} else if 0 < len(setting.CpeURIs) {
			fvulsClient := fvuls.NewClient(c.Token, c.Proxy)
			var serverDetail fvuls.ServerDetailOutput
			if serverDetail, err = fvulsClient.GetServerByUUID(ctx, setting.UUID); err != nil {
				fmt.Printf("%s: Failed to Fetch serverID. err: %v\n", name, err)
				continue
			}

			// update server name
			server := c.OriginalDiscoverToml[name]
			server.ServerName = serverDetail.ServerName
			c.OriginalDiscoverToml[name] = server

			var uploadedCpes []string
			if uploadedCpes, err = fvulsClient.ListUploadedCPE(ctx, serverDetail.ServerID); err != nil {
				fmt.Printf("%s: Failed to Fetch uploaded CPE. err: %v\n", name, err)
				continue
			}

			// check if there are any CPEs that are not uploaded
			var newCpes []string
			for _, cpeURI := range setting.CpeURIs {
				if !slices.Contains(uploadedCpes, cpeURI) {
					newCpes = append(newCpes, cpeURI)
				}
			}
			if 0 < len(newCpes) {
				setting.NewCpeURIs = newCpes
				needAddCpes[name] = setting
			}
		}
	}

	if len(needAddServers)+len(needAddCpes) == 0 {
		fmt.Printf("There are no hosts to add to Fvuls\n")
		return nil, nil, nil
	}
	return needAddServers, needAddCpes, nil
}

// AddServerToFvuls ...
func (c *AddCpeConfig) AddServerToFvuls(ctx context.Context, needAddServers map[string]config.ServerSetting) (addedServers config.DiscoverToml) {
	fmt.Printf("Creating %d pseudo server...\n", len(needAddServers))
	fvulsClient := fvuls.NewClient(c.Token, c.Proxy)
	addedServers = make(map[string]config.ServerSetting)
	for name, server := range needAddServers {
		var serverDetail fvuls.ServerDetailOutput
		serverDetail, err := fvulsClient.CreatePseudoServer(ctx, server.ServerName)
		if err != nil {
			fmt.Printf("%s: Failed to add to Fvuls server. err: %v\n", server.ServerName, err)
			continue
		}
		server.UUID = serverDetail.ServerUUID
		server.ServerName = serverDetail.ServerName
		addedServers[name] = server
		fmt.Printf("%s: Created FutureVuls pseudo server %s\n", server.ServerName, server.UUID)
	}
	return addedServers
}

// AddCpeToFvuls ...
func (c *AddCpeConfig) AddCpeToFvuls(ctx context.Context, needAddCpes config.DiscoverToml) (config.DiscoverToml, error) {
	fmt.Printf("Uploading %d server's CPE...\n", len(needAddCpes))
	fvulsClient := fvuls.NewClient(c.Token, c.Proxy)
	for name, server := range needAddCpes {
		serverDetail, err := fvulsClient.GetServerByUUID(ctx, server.UUID)
		server.ServerName = serverDetail.ServerName
		if err != nil {
			fmt.Printf("%s: Failed to Fetch serverID. err: %v\n", server.ServerName, err)
			continue
		}
		for _, cpeURI := range server.NewCpeURIs {
			if err = fvulsClient.UploadCPE(ctx, cpeURI, serverDetail.ServerID); err != nil {
				fmt.Printf("%s: Failed to upload CPE %s. err: %v\n", server.ServerName, cpeURI, err)
				continue
			}
			fmt.Printf("%s: Uploaded CPE %s\n", server.ServerName, cpeURI)
		}
		needAddCpes[name] = server
	}
	return needAddCpes, nil
}

// WriteDiscoverToml ...
func (c *AddCpeConfig) WriteDiscoverToml() error {
	f, err := os.OpenFile(c.DiscoverTomlPath, os.O_RDWR|os.O_TRUNC, 0666)
	if err != nil {
		return fmt.Errorf("failed to open toml file. err: %v", err)
	}
	defer f.Close()
	encoder := toml.NewEncoder(f)
	if err := encoder.Encode(c.OriginalDiscoverToml); err != nil {
		return fmt.Errorf("failed to write to %s. err: %v", c.DiscoverTomlPath, err)
	}
	fmt.Printf("wrote to %s\n\n", c.DiscoverTomlPath)
	return nil
}
