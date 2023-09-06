package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/cpe"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/discover"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/saas"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/schema"
	"github.com/future-architect/vuls/contrib/future-vuls/pkg/server"

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
	url         string
	outputFile  string
	cidr        string
	snmpVersion string
	proxy       string
)

func main() {
	var err error
	var cmdFvulsUploader = &cobra.Command{
		Use:   "upload",
		Short: "Upload to FutureVuls",
		Long:  `Upload to FutureVuls`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(serverUUID) == 0 {
				serverUUID = os.Getenv("VULS_SERVER_UUID")
			}
			if groupID == 0 {
				envGroupID := os.Getenv("VULS_GROUP_ID")
				if groupID, err = strconv.ParseInt(envGroupID, 10, 64); err != nil {
					return fmt.Errorf("invalid GroupID: %s", envGroupID)
				}
			}
			if len(url) == 0 {
				url = os.Getenv("VULS_URL")
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
			if err := saas.UploadToFvuls(serverUUID, groupID, url, token, tags, scanResultJSON); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			return nil
		},
	}
	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Long:  "Show version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("future-vuls-%s-%s\n", config.Version, config.Revision)
		},
	}

	var cmdDiscover = &cobra.Command{
		Use:     "discover --cidr <CIDR_RANGE> --output <OUTPUT_FILE>",
		Short:   "discover hosts with CIDR range. Default outputFile is ./discover_list.toml",
		Example: "future-vuls discover --cidr 192.168.0.0/24 --output discover_list.toml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(outputFile) == 0 {
				outputFile = schema.FILENAME
			}
			if len(cidr) == 0 {
				return fmt.Errorf("please specify cidr range")
			}
			if err := discover.ActiveHosts(cidr, outputFile); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			return nil
		},
	}

	var cmdAddServer = &cobra.Command{
		Use:     "add-server --token <VULS_TOKEN> --output <OUTPUT_FILE>",
		Short:   "upload device information to Fvuls as a pseudo server. Default outputFile is ./discover_list.toml",
		Example: "future-vuls add-server --token <VULS_TOKEN> --output ./discover_list.toml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(token) == 0 {
				token = os.Getenv("VULS_TOKEN")
			}
			if len(outputFile) == 0 {
				outputFile = schema.FILENAME
			}
			if len(url) == 0 {
				url = os.Getenv("VULS_URL")
			}
			if err := server.AddServerToFvuls(token, outputFile, proxy); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			return nil
		},
	}

	var cmdAddCpe = &cobra.Command{
		Use:     "add-cpe --token <VULS_TOKEN> --output <OUTPUT_FILE>",
		Short:   "scan device CPE and upload to Fvuls server. Default outputFile is ./discover_list.toml",
		Example: "future-vuls add-cpe --token <VULS_TOKEN>",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(token) == 0 {
				token = os.Getenv("VULS_TOKEN")
			}
			if len(outputFile) == 0 {
				outputFile = schema.FILENAME
			}
			if len(url) == 0 {
				url = os.Getenv("VULS_URL")
			}
			if len(snmpVersion) == 0 {
				snmpVersion = schema.SNMPVERSION
			}
			if err := cpe.AddCpeDataToFvuls(token, snmpVersion, outputFile, proxy); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			return nil
		},
	}

	cmdDiscover.PersistentFlags().StringVar(&cidr, "cidr", "", "cidr range")
	cmdDiscover.PersistentFlags().StringVar(&outputFile, "output", "", "output file")
	cmdAddServer.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token ENV: VULS_TOKEN")
	cmdAddServer.PersistentFlags().StringVar(&outputFile, "output", "", "output file")
	cmdAddServer.PersistentFlags().StringVar(&proxy, "http-proxy", "", "proxy url")
	cmdAddCpe.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token ENV: VULS_TOKEN")
	cmdAddCpe.PersistentFlags().StringVar(&outputFile, "output", "", "output file")
	cmdAddCpe.PersistentFlags().StringVar(&snmpVersion, "snmp-version", "", "snmp version v1,v2c and v3. default: v2c ")
	cmdAddCpe.PersistentFlags().StringVar(&proxy, "http-proxy", "", "proxy url")

	cmdFvulsUploader.PersistentFlags().StringVar(&serverUUID, "uuid", "", "server uuid. ENV: VULS_SERVER_UUID")
	cmdFvulsUploader.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	cmdFvulsUploader.PersistentFlags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin. ENV: VULS_STDIN")
	// TODO Read JSON file from directory
	//	cmdFvulsUploader.Flags().StringVarP(&jsonDir, "results-dir", "d", "./", "vuls scan results json dir")
	cmdFvulsUploader.PersistentFlags().Int64VarP(&groupID, "group-id", "g", 0, "future vuls group id, ENV: VULS_GROUP_ID")
	cmdFvulsUploader.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token")

	var rootCmd = &cobra.Command{Use: "future-vuls"}
	rootCmd.AddCommand(cmdAddServer)
	rootCmd.AddCommand(cmdDiscover)
	rootCmd.AddCommand(cmdAddCpe)
	rootCmd.AddCommand(cmdFvulsUploader)
	rootCmd.AddCommand(cmdVersion)
	if err = rootCmd.Execute(); err != nil {
		fmt.Println("Failed to execute command")
	}
}
