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
	"github.com/future-architect/vuls/report"
	"github.com/spf13/cobra"
)

var (
	configFile string
	stdIn      bool
	jsonDir    string
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
			envGroupID := os.Getenv("VULS_GROUP_ID")
			if 0 < len(envGroupID) {
				if groupID, err = strconv.ParseInt(envGroupID, 10, 64); err != nil {
					fmt.Printf("Invalid GroupID: %s\n", envGroupID)
					return
				}
			}
			envURL := os.Getenv("VULS_URL")
			if 0 < len(envURL) {
				url = envURL
			}
			envToken := os.Getenv("VULS_TOKEN")
			if 0 < len(envToken) {
				token = envToken
			}

			var scanResultJSON []byte
			if stdIn {
				reader := bufio.NewReader(os.Stdin)
				buf := new(bytes.Buffer)
				buf.ReadFrom(reader)
				scanResultJSON = buf.Bytes()
			} else {
				fmt.Println("use --stdin option")
				return
			}

			var scanResult models.ScanResult
			if err = json.Unmarshal(scanResultJSON, &scanResult); err != nil {
				fmt.Println("Failed to parse json", err)
				return
			}

			config.Conf.Saas.GroupID = groupID
			config.Conf.Saas.Token = token
			config.Conf.Saas.URL = url
			if err = (report.SaasWriter{}).Write(scanResult); err != nil {
				fmt.Println("Failed to create json", err)
				return
			}
			return
		},
	}
	cmdFvulsUploader.PersistentFlags().StringVar(&configFile, "config", "", "config file (default is $HOME/.cobra.yaml)")
	cmdFvulsUploader.PersistentFlags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin. ENV: VULS_STDIN")
	// TODO Read JSON file from directory
	//	cmdFvulsUploader.Flags().StringVarP(&jsonDir, "results-dir", "d", "./", "vuls scan results json dir")
	cmdFvulsUploader.PersistentFlags().Int64VarP(&groupID, "group-id", "g", 0, "future vuls group id, ENV: VULS_GROUP_ID")
	cmdFvulsUploader.PersistentFlags().StringVarP(&token, "token", "t", "", "future vuls token")
	cmdFvulsUploader.PersistentFlags().StringVarP(&url, "url", "u", "", "future vuls upload url")

	var rootCmd = &cobra.Command{Use: "future-vuls"}
	rootCmd.AddCommand(cmdFvulsUploader)
	if err = rootCmd.Execute(); err != nil {
		fmt.Println("Failed to execute command", err)
	}
}
