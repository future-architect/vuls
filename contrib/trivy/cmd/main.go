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
		Short: "Parse trivy json to vuls results",
		Long:  `Parse trivy json to vuls results`,
		Run: func(cmd *cobra.Command, args []string) {
			jsonFilePath := filepath.Join(jsonDir, jsonFileName)
			var trivyJSON []byte
			if stdIn {
				reader := bufio.NewReader(os.Stdin)
				buf := new(bytes.Buffer)
				if _, err = buf.ReadFrom(reader); err != nil {
					fmt.Printf("Failed to read file. err: %+v", err)
					os.Exit(1)
				}
				trivyJSON = buf.Bytes()
			} else {
				if trivyJSON, err = ioutil.ReadFile(jsonFilePath); err != nil {
					fmt.Printf("Failed to read file. err: %+v", err)
					os.Exit(1)
				}
			}

			scanResult := &models.ScanResult{
				JSONVersion: models.JSONVersion,
				ScannedCves: models.VulnInfos{},
			}
			parser, err := parser.NewParser(trivyJSON)
			if err != nil {
				fmt.Printf("Failed to new parser. err: %+v", err)
				os.Exit(1)
			}
			if scanResult, err = parser.Parse(trivyJSON, scanResult); err != nil {
				fmt.Printf("Failed to parse. err: %+v", err)
				os.Exit(1)
			}
			var resultJSON []byte
			if resultJSON, err = json.MarshalIndent(scanResult, "", "   "); err != nil {
				fmt.Printf("Failed to create json. err: %+v", err)
				os.Exit(1)
			}
			fmt.Println(string(resultJSON))
		},
	}
	cmdTrivyToVuls.Flags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin")
	cmdTrivyToVuls.Flags().StringVarP(&jsonDir, "trivy-json-dir", "d", "./", "trivy json dir")
	cmdTrivyToVuls.Flags().StringVarP(&jsonFileName, "trivy-json-file-name", "f", "results.json", "trivy json file name")

	var rootCmd = &cobra.Command{Use: "trivy-to-vuls"}
	rootCmd.AddCommand(cmdTrivyToVuls)
	if err = rootCmd.Execute(); err != nil {
		fmt.Printf("Failed to execute command. err: %+v", err)
		os.Exit(1)
	}
}
