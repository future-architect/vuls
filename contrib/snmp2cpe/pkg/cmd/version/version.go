package version

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/config"
)

// NewCmdVersion ...
func NewCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintf(os.Stdout, "snmp2cpe %s %s\n", config.Version, config.Revision); err != nil {
				return errors.Wrap(err, "failed to print version")
			}
			return nil
		},
	}
	return cmd
}
