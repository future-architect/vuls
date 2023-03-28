package main

import (
	"fmt"
	"os"

	rootCmd "github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cmd/root"
)

func main() {
	if err := rootCmd.NewCmdRoot().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to exec snmp2cpe: %s\n", fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}
