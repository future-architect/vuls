package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/spf13/cobra"
)

var (
	stdIn   bool
	jsonDir string
	groupID int64
	token   string
	url     string
)

func main() {
	var err error
	var cmdTrivyToVuls = &cobra.Command{
		Use:   "upload",
		Short: "Upload to FutureVuls",
		Long:  `Upload to FutureVuls`,
		Run: func(cmd *cobra.Command, args []string) {
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
	cmdTrivyToVuls.Flags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin")
	// TODO Read JSON file from directory
	//	cmdTrivyToVuls.Flags().StringVarP(&jsonDir, "results-dir", "d", "./", "vuls scan results json dir")
	cmdTrivyToVuls.Flags().Int64VarP(&groupID, "group-id", "g", 0, "future vuls group id")
	cmdTrivyToVuls.MarkFlagRequired("group-id")
	cmdTrivyToVuls.Flags().StringVarP(&token, "token", "t", "", "future vuls token")
	cmdTrivyToVuls.MarkFlagRequired("token")
	cmdTrivyToVuls.Flags().StringVarP(&url, "url", "u", "", "future vuls upload url")
	cmdTrivyToVuls.MarkFlagRequired("url")

	var rootCmd = &cobra.Command{Use: "future-vuls"}
	rootCmd.AddCommand(cmdTrivyToVuls)
	if err = rootCmd.Execute(); err != nil {
		fmt.Println("Failed to execute command", err)
	}
}
