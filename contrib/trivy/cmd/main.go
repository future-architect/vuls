package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/contrib/trivy/parser"
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
		Run: func(_ *cobra.Command, _ []string) {
			jsonFilePath := filepath.Join(jsonDir, jsonFileName)
			var trivyJSON []byte
			if stdIn {
				reader := bufio.NewReader(os.Stdin)
				buf := new(bytes.Buffer)
				if _, err = buf.ReadFrom(reader); err != nil {
					fmt.Printf("Failed to read file. err: %+v\n", err)
					os.Exit(1)
				}
				trivyJSON = buf.Bytes()
			} else {
				if trivyJSON, err = os.ReadFile(jsonFilePath); err != nil {
					fmt.Printf("Failed to read file. err: %+v\n", err)
					os.Exit(1)
				}
			}

			parser, err := parser.NewParser(trivyJSON)
			if err != nil {
				fmt.Printf("Failed to new parser. err: %+v\n", err)
				os.Exit(1)
			}
			scanResult, err := parser.Parse(trivyJSON)
			if err != nil {
				fmt.Printf("Failed to parse. err: %+v\n", err)
				os.Exit(1)
			}
			var resultJSON []byte
			if resultJSON, err = json.MarshalIndent(scanResult, "", "   "); err != nil {
				fmt.Printf("Failed to create json. err: %+v\n", err)
				os.Exit(1)
			}
			fmt.Println(string(resultJSON))
		},
	}

	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Show version",
		Long:  "Show version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Printf("trivy-to-vuls-%s-%s\n", config.Version, config.Revision)
		},
	}

	cmdTrivyToVuls.Flags().BoolVarP(&stdIn, "stdin", "s", false, "input from stdin")
	cmdTrivyToVuls.Flags().StringVarP(&jsonDir, "trivy-json-dir", "d", "./", "trivy json dir")
	cmdTrivyToVuls.Flags().StringVarP(&jsonFileName, "trivy-json-file-name", "f", "results.json", "trivy json file name")

	var rootCmd = &cobra.Command{Use: "trivy-to-vuls"}
	rootCmd.AddCommand(cmdTrivyToVuls)
	rootCmd.AddCommand(cmdVersion)
	if err = rootCmd.Execute(); err != nil {
		fmt.Printf("Failed to execute command. err: %+v\n", err)
		os.Exit(1)
	}
	os.Exit(0)
}
