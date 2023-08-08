package discover

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	ps "github.com/kotakanbe/go-pingscanner"
)

func ActiveHosts(cidr string, outputFile string) error {
	scanner := ps.PingScanner{
		CIDR: cidr,
		PingOptions: []string{
			"-c1",
		},
		NumOfConcurrency: 100,
	}
	fmt.Printf("Discovering %s...\n", cidr)
	hosts, err := scanner.Scan()
	if err != nil {
		return fmt.Errorf("host Discovery failed. err: %v", err)
	}
	if len(hosts) < 1 {
		return fmt.Errorf("active hosts not found in %s", cidr)
	}

	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("failed to open toml file. err: %v", err)
	}
	defer f.Close()
	var prevDiscoverResult map[string]schema.ServerDetail
	_, err = toml.DecodeFile(outputFile, &prevDiscoverResult)
	if err != nil {
		return fmt.Errorf("failed to read previous discovery result. err: %v", err)
	}

	servers := make(map[string]schema.ServerDetail)
	for _, host := range hosts {
		if _, ok := prevDiscoverResult[host]; !ok {
			server := schema.ServerDetail{
				IP:        host,
				FvulsSync: false,
			}
			servers[host] = server
			fmt.Printf("New host found %s\n", host)
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("new host could not be found")
	}
	encoder := toml.NewEncoder(f)
	if err = encoder.Encode(servers); err != nil {
		return fmt.Errorf("failed to write to %s. err: %v", outputFile, err)
	}
	fmt.Printf("Successfully wrote to %s\n", outputFile)
	return nil
}
