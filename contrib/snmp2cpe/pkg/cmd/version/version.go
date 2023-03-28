package version

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/config"
)

// NewCmdVersion ...
func NewCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Fprintf(os.Stdout, "snmp2cpe %s %s\n", config.Version, config.Revision)
		},
	}
	return cmd
}
