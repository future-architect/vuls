package discover

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	ps "github.com/kotakanbe/go-pingscanner"
)

func DiscoverActiveHosts(cidr string, outputFile string) error {
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
		return fmt.Errorf("Host Discovery failed. err: %v\n", err)
	}
	if len(hosts) < 1 {
		return fmt.Errorf("Active hosts not found in %s\n", cidr)
	}

	f, err := os.OpenFile(outputFile, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		return fmt.Errorf("Failed to open toml file. err: %v\n", err)
	}
	defer f.Close()
	var prevDiscoverResult map[string]schema.ServerDetail
	_, err = toml.DecodeFile(outputFile, &prevDiscoverResult)
	if err != nil {
		return fmt.Errorf("Failed to read previous discovery result. err: %v\n", err)
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
		return fmt.Errorf("New host could not be found.\n")
	}
	encoder := toml.NewEncoder(f)
	if err = encoder.Encode(servers); err != nil {
		return fmt.Errorf("Failed to write to %s. err: %v", outputFile, err)
	}
	fmt.Printf("Successfully wrote to %s\n", outputFile)
	return nil
}
