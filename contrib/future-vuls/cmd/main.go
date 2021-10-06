package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/saas"
	"github.com/spf13/cobra"
)

var (
	configFile string
	stdIn      bool
	jsonDir    string
	serverUUID string
	groupID    int64
	token      string
	url        string
)

func main() {
	var err error
	var cmdFvulsUploader = &cobra.Command{
		Use:   "upload",
		Short: "Upload to FutureVuls",
		Long:  `Upload to FutureVuls`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(serverUUID) == 0 {
				serverUUID = os.Getenv("VULS_SERVER_UUID")
			}
			if groupID == 0 {
				envGroupID := os.Getenv("VULS_GROUP_ID")
				if groupID, err = strconv.ParseInt(envGroupID, 10, 64); err != nil {
					fmt.Printf("Invalid GroupID: %s\n", envGroupID)
					return
				}
			}
			if len(url) == 0 {
				url = os.Getenv("VULS_URL")
			}
			if len(token) == 0 {
				token = os.Getenv("VULS_TOKEN")
			}

			var scanResultJSON []byte
			if stdIn {
				reader := bufio.NewReader(os.Stdin)
				buf := new(bytes.Buffer)
				if _, err = buf.ReadFrom(reader); err != nil {
					return
				}
				scanResultJSON = buf.Bytes()
			} else {
				fmt.Println("use --stdin option")
				os.Exit(1)
				return
			}

			var scanResult models.ScanResult
			if err = json.Unmarshal(scanResultJSON, &scanResult); err != nil {
				fmt.Println("Failed to parse json", err)
				os.Exit(1)
				return
			}
			scanResult.ServerUUID = serverUUID

			config.Conf.Saas.GroupID = groupID
			config.Conf.Saas.Token = token
			config.Conf.Saas.URL = url
			if err = (saas.Writer{}).Write(scanResult); err != nil {
				fmt.Println(err)
				os.Exit(1)
				return
			}
			return
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
	cmdFvulsUploader.PersistentFlags().StringVar(&serverUUID, "uuid", "", "server uuid. ENV: VULS_SERVER_UUID")
	cmdFvulsUploader.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	cmdFvulsUploader.PersistentFlags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin. ENV: VULS_STDIN")
	// TODO Read JSON file from directory
	//	cmdFvulsUploader.Flags().StringVarP(&jsonDir, "results-dir", "d", "./", "vuls scan results json dir")
	cmdFvulsUploader.PersistentFlags().Int64VarP(&groupID, "group-id", "g", 0, "future vuls group id, ENV: VULS_GROUP_ID")
	cmdFvulsUploader.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token")
	cmdFvulsUploader.PersistentFlags().StringVar(&url, "url", "", "future vuls upload url")

	var rootCmd = &cobra.Command{Use: "future-vuls"}
	rootCmd.AddCommand(cmdFvulsUploader)
	rootCmd.AddCommand(cmdVersion)
	if err = rootCmd.Execute(); err != nil {
		fmt.Println("Failed to execute command", err)
	}
}
