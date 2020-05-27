package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/contrib/trivy/parser"
	"github.com/future-architect/vuls/models"
	"github.com/spf13/cobra"
)

var (
	serverUUID   string
	stdIn        bool
	jsonDir      string
	jsonFileName string
)

func main() {
	var err error
	var cmdTrivyToVuls = &cobra.Command{
		Use:   "parse",
		Short: "Parse Trivy JSON to vuls results",
		Long:  `Parse Trivy JSON to vuls results`,
		Run: func(cmd *cobra.Command, args []string) {
			jsonFilePath := filepath.Join(jsonDir, jsonFileName)
			var trivyJSON []byte
			if stdIn {
				reader := bufio.NewReader(os.Stdin)
				buf := new(bytes.Buffer)
				buf.ReadFrom(reader)
				trivyJSON = buf.Bytes()
			} else {
				if trivyJSON, err = ioutil.ReadFile(jsonFilePath); err != nil {
					fmt.Println("Failed to read file", err)
					return
				}
			}

			scanResult := &models.ScanResult{
				JSONVersion: models.JSONVersion,
				ServerUUID:  serverUUID,
				ScannedCves: models.VulnInfos{},
			}
			if scanResult, err = parser.Parse(trivyJSON, scanResult); err != nil {
				fmt.Println("Failed to execute command", err)
				return
			}
			var resultJSON []byte
			if resultJSON, err = json.MarshalIndent(scanResult, "", "   "); err != nil {
				fmt.Println("Failed to create json", err)
				return
			}
			fmt.Println(string(resultJSON))
			return
		},
	}
	cmdTrivyToVuls.Flags().StringVarP(&serverUUID, "uuid", "u", "", "server uuid")
	cmdTrivyToVuls.MarkFlagRequired("uuid")
	cmdTrivyToVuls.Flags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin")
	cmdTrivyToVuls.Flags().StringVarP(&jsonDir, "trivy-json-dir", "d", "./", "trivy json dir")
	cmdTrivyToVuls.Flags().StringVarP(&jsonFileName, "trivy-json-file-name", "f", "results.json", "trivy json file name")

	var rootCmd = &cobra.Command{Use: "trivy-to-vuls"}
	rootCmd.AddCommand(cmdTrivyToVuls)
	if err = rootCmd.Execute(); err != nil {
		fmt.Println("Failed to execute command", err)
	}
}
