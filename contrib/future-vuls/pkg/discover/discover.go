// Package discover ...
package discover

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/kotakanbe/go-pingscanner"

	"github.com/future-architect/vuls/contrib/future-vuls/pkg/config"
)

// ActiveHosts ...
func ActiveHosts(cidr, outputFile, snmpVersion, community string, timeout time.Duration, retry int) error {
	scanner := pingscanner.PingScanner{
		CIDR: cidr,
		PingOptions: func() []string {
			switch runtime.GOOS {
			case "windows":
				return []string{"-n", "1"}
			default:
				return []string{"-c", "1"}
			}
		}(),
		NumOfConcurrency: 100,
	}
	fmt.Printf("Discovering %s...\n", cidr)
	activeHosts, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("host Discovery failed. err: %v", err)
	}
	if len(activeHosts) == 0 {
		return fmt.Errorf("active hosts not found in %s", cidr)
	}

	discoverToml := config.DiscoverToml{}
	if _, err := os.Stat(outputFile); err == nil {
		fmt.Printf("%s is found.\n", outputFile)
		if _, err = toml.DecodeFile(outputFile, &discoverToml); err != nil {
			return fmt.Errorf("failed to read discover toml: %s", outputFile)
		}
	}

	servers := make(config.DiscoverToml)
	for _, activeHost := range activeHosts {
		cpes, err := executeSnmp2cpe(activeHost, snmpVersion, community, timeout, retry)
		if err != nil {
			fmt.Printf("failed to execute snmp2cpe. err: %v\n", err)
			continue
		}

		fvulsSync := false
		serverUUID := ""
		serverName := activeHost
		if server, ok := discoverToml[activeHost]; ok {
			fvulsSync = server.FvulsSync
			serverUUID = server.UUID
			serverName = server.ServerName
		} else {
			fmt.Printf("New network device found %s\n", activeHost)
		}

		servers[activeHost] = config.ServerSetting{
			IP:         activeHost,
			ServerName: serverName,
			UUID:       serverUUID,
			FvulsSync:  fvulsSync,
			CpeURIs:    cpes[activeHost],
		}
	}

	for ip, setting := range discoverToml {
		if _, ok := servers[ip]; !ok {
			fmt.Printf("%s(%s) has been removed as there was no response.\n", setting.ServerName, setting.IP)
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("new network devices could not be found")
	}

	if 0 < len(discoverToml) {
		fmt.Printf("Creating new %s and saving the old file under different name...\n", outputFile)
		timestamp := time.Now().Format(config.DiscoverTomlTimeStampFormat)
		oldDiscoverFile := fmt.Sprintf("%s_%s", timestamp, outputFile)
		if err := os.Rename(outputFile, oldDiscoverFile); err != nil {
			return fmt.Errorf("failed to rename exist toml file. err: %v", err)
		}
		fmt.Printf("You can check the difference from the previous DISCOVER with the following command.\n  diff %s %s\n", outputFile, oldDiscoverFile)
	}

	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("failed to open toml file. err: %v", err)
	}
	defer f.Close()
	encoder := toml.NewEncoder(f)
	if err = encoder.Encode(servers); err != nil {
		return fmt.Errorf("failed to write to %s. err: %v", outputFile, err)
	}
	fmt.Printf("wrote to %s\n", outputFile)
	return nil
}

func executeSnmp2cpe(addr, snmpVersion, community string, timeout time.Duration, retry int) (cpes map[string][]string, err error) {
	fmt.Printf("%s: Execute snmp2cpe...\n", addr)
	result, err := exec.Command("./snmp2cpe", snmpVersion, "--timeout", timeout.String(), "--retry", fmt.Sprintf("%d", retry), addr, community).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute snmp2cpe. err: %v", err)
	}
	cmd := exec.Command("./snmp2cpe", "convert")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to convert snmp2cpe result. err: %v", err)
	}
	if _, err := stdin.Write(result); err != nil {
		return nil, fmt.Errorf("failed to write to stdIn. err: %v", err)
	}
	if err := stdin.Close(); err != nil {
		return nil, fmt.Errorf("failed to close stdIn. err: %v", err)
	}
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to convert snmp2cpe result. err: %v", err)
	}

	if err := json.Unmarshal(output, &cpes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snmp2cpe output. err: %v", err)
	}
	return cpes, nil
}
