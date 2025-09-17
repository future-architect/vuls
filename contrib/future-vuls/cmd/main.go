// Package main ...
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	vulsConfig "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/config"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/cpe"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/discover"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/fvuls"

	"github.com/spf13/cobra"
)

var (
	configFile  string
	stdIn       bool
	jsonDir     string
	serverUUID  string
	groupID     int64
	token       string
	tags        []string
	outputFile  string
	cidr        string
	snmpVersion string
	proxy       string
	community   string
)

func main() {
	var err error
	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Long:  "Show version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("future-vuls-%s-%s\n", vulsConfig.Version, vulsConfig.Revision)
		},
	}

	var cmdFvulsUploader = &cobra.Command{
		Use:   "upload",
		Short: "Upload to FutureVuls",
		Long:  `Upload to FutureVuls`,
		RunE: func(_ *cobra.Command, _ []string) error {
			if len(serverUUID) == 0 {
				serverUUID = os.Getenv("VULS_SERVER_UUID")
			}
			if groupID == 0 {
				envGroupID := os.Getenv("VULS_GROUP_ID")
				if groupID, err = strconv.ParseInt(envGroupID, 10, 64); err != nil {
					return fmt.Errorf("invalid GroupID: %s", envGroupID)
				}
			}
			if len(token) == 0 {
				token = os.Getenv("VULS_TOKEN")
			}
			if len(tags) == 0 {
				tags = strings.Split(os.Getenv("VULS_TAGS"), ",")
			}
			var scanResultJSON []byte
			if stdIn {
				reader := bufio.NewReader(os.Stdin)
				buf := new(bytes.Buffer)
				if _, err := buf.ReadFrom(reader); err != nil {
					return fmt.Errorf("failed to read from stdIn. err: %v", err)
				}
				scanResultJSON = buf.Bytes()
			} else {
				return fmt.Errorf("use --stdin option")
			}
			fvulsClient := fvuls.NewClient(token, "")
			if err := fvulsClient.UploadToFvuls(serverUUID, groupID, tags, scanResultJSON); err != nil {
				fmt.Printf("%v", err)
				// avoid to display help message
				os.Exit(1)
			}
			return nil
		},
	}

	var cmdDiscover = &cobra.Command{
		Use:     "discover --cidr <CIDR_RANGE> --output <OUTPUT_FILE>",
		Short:   "discover hosts with CIDR range. Run snmp2cpe on active host to get CPE. Default outputFile is ./discover_list.toml",
		Example: "future-vuls discover --cidr 192.168.0.0/24 --output discover_list.toml",
		RunE: func(_ *cobra.Command, _ []string) error {
			if len(outputFile) == 0 {
				outputFile = config.DiscoverTomlFileName
			}
			if len(cidr) == 0 {
				return fmt.Errorf("please specify cidr range")
			}
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("Invalid cidr range")
			}
			if len(snmpVersion) == 0 {
				snmpVersion = config.SnmpVersion
			}
			if snmpVersion != "v1" && snmpVersion != "v2c" && snmpVersion != "v3" {
				return fmt.Errorf("Invalid snmpVersion")
			}
			if community == "" {
				community = config.Community
			}
			if err := discover.ActiveHosts(cidr, outputFile, snmpVersion, community); err != nil {
				fmt.Printf("%v", err)
				// avoid to display help message
				os.Exit(1)
			}
			return nil
		},
	}

	var cmdAddCpe = &cobra.Command{
		Use:     "add-cpe --token <VULS_TOKEN> --output <OUTPUT_FILE>",
		Short:   "Create a pseudo server in Fvuls and register CPE. Default outputFile is ./discover_list.toml",
		Example: "future-vuls add-cpe --token <VULS_TOKEN>",
		RunE: func(_ *cobra.Command, _ []string) error {
			if len(token) == 0 {
				token = os.Getenv("VULS_TOKEN")
				if len(token) == 0 {
					return fmt.Errorf("token not specified")
				}
			}
			if len(outputFile) == 0 {
				outputFile = config.DiscoverTomlFileName
			}
			if err := cpe.AddCpe(token, outputFile, proxy); err != nil {
				fmt.Printf("%v", err)
				// avoid to display help message
				os.Exit(1)
			}
			return nil
		},
	}

	cmdFvulsUploader.PersistentFlags().StringVar(&serverUUID, "uuid", "", "server uuid. ENV: VULS_SERVER_UUID")
	cmdFvulsUploader.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	cmdFvulsUploader.PersistentFlags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin. ENV: VULS_STDIN")
	cmdFvulsUploader.PersistentFlags().Int64VarP(&groupID, "group-id", "g", 0, "future vuls group id, ENV: VULS_GROUP_ID")
	cmdFvulsUploader.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token")

	cmdDiscover.PersistentFlags().StringVar(&cidr, "cidr", "", "cidr range")
	cmdDiscover.PersistentFlags().StringVar(&outputFile, "output", "", "output file")
	cmdDiscover.PersistentFlags().StringVar(&snmpVersion, "snmp-version", "", "snmp version v1,v2c and v3. default: v2c")
	cmdDiscover.PersistentFlags().StringVar(&community, "community", "", "snmp community name. default: public")

	cmdAddCpe.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token ENV: VULS_TOKEN")
	cmdAddCpe.PersistentFlags().StringVar(&outputFile, "output", "", "output file")
	cmdAddCpe.PersistentFlags().StringVar(&proxy, "http-proxy", "", "proxy url")

	var rootCmd = &cobra.Command{Use: "future-vuls"}
	rootCmd.AddCommand(cmdDiscover)
	rootCmd.AddCommand(cmdAddCpe)
	rootCmd.AddCommand(cmdFvulsUploader)
	rootCmd.AddCommand(cmdVersion)
	if err = rootCmd.Execute(); err != nil {
		fmt.Println("Failed to execute command")
	}
}
