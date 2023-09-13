// discover
package discover

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	ps "github.com/kotakanbe/go-pingscanner"
	"golang.org/x/exp/maps"
)

// ActiveHosts ...
func ActiveHosts(cidr string, outputFile string, snmpVersion string) error {
	scanner := ps.PingScanner{
		CIDR: cidr,
		PingOptions: []string{
			"-c1",
		},
		NumOfConcurrency: 100,
	}
	fmt.Printf("Discovering %s...\n", cidr)
	activeHosts, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("host Discovery failed. err: %v", err)
	}
	if len(activeHosts) < 1 {
		return fmt.Errorf("active hosts not found in %s", cidr)
	}

	var prevDiscoverFile string
	var prevDiscoverResult map[string]*schema.ServerDetail
	if _, err := os.Stat(outputFile); err != nil {
		fmt.Printf("%s is not found. Creating...\n", outputFile)
	} else {
		_, err = toml.DecodeFile(outputFile, &prevDiscoverResult)
		if err != nil {
			return fmt.Errorf("failed to read previous discovery result. err: %v", err)
		}
		currentTime := time.Now()
		timestamp := currentTime.Format(schema.TIMESTAMPFORMAT)
		prevDiscoverFile = fmt.Sprintf("%s_%s", timestamp, outputFile)
		err := os.Rename(outputFile, prevDiscoverFile)
		if err != nil {
			return fmt.Errorf("failed to rename exist toml file. err: %v", err)
		}
	}

	servers := make(map[string]*schema.ServerDetail)
	for _, activeHost := range activeHosts {
		cpeData, err := executeSnmp2cpe(activeHost, snmpVersion)
		if err != nil {
			fmt.Printf("failed to execute snmp2cpe. err: %v\n", err)
			continue
		}
		if _, ok := prevDiscoverResult[activeHost]; !ok {
			server := schema.ServerDetail{
				IP:         activeHost,
				ServerName: activeHost,
				FvulsSync:  false,
				CpeURI:     cpeData[activeHost],
			}
			servers[activeHost] = &server
			fmt.Printf("New network device found %s\n", activeHost)
		} else if !reflect.DeepEqual(prevDiscoverResult[activeHost].CpeURI, cpeData[activeHost]) {
			fmt.Printf("A difference was found in CPE. Updating...\n")
			prevDiscoverResult[activeHost].CpeURI = cpeData[activeHost]
		}
	}
	if len(servers) == 0 {
		fmt.Printf("new network devices could not be found\n")
	}
	maps.Copy(servers, prevDiscoverResult)

	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("failed to open toml file. err: %v", err)
	}
	defer f.Close()
	encoder := toml.NewEncoder(f)
	if err = encoder.Encode(servers); err != nil {
		return fmt.Errorf("failed to write to %s. err: %v", outputFile, err)
	}
	fmt.Printf("Successfully wrote to %s\n", outputFile)
	if prevDiscoverFile != "" {
		fmt.Printf("You can check the difference from the previous DISCOVER with the following command.\n  diff %s %s", outputFile, prevDiscoverFile)
	}
	return nil
}

func executeSnmp2cpe(addr string, snmpVersion string) (map[string][]string, error) {
	fmt.Printf("%s: Execute snmp2cpe...\n", addr)
	result, err := exec.Command("./snmp2cpe", snmpVersion, addr, "public").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute snmp2cpe. err: %v", err)
	}
	cmd := exec.Command("./snmp2cpe", "convert")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to convert snmp2cpe result. err: %v", err)
	}
	if _, err := io.WriteString(stdin, string(result)); err != nil {
		return nil, fmt.Errorf("failed to write to stdIn. err: %v", err)
	}
	stdin.Close()
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to convert snmp2cpe result. err: %v", err)
	}

	var jsonData map[string][]string
	if err := json.Unmarshal(output, &jsonData); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snmp2cpe output. err: %v", err)
	}
	return jsonData, nil
}
