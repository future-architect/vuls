package version

import (
	"fmt"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
)

// Version and Revision are set via ldflags at build time.
var (
	Version  = "unknown"
	Revision = "unknown"
)

// NewCmdVersion ...
func NewCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintf(os.Stdout, "snmp2cpe %s %s\n", Version, Revision); err != nil {
				return errors.Wrap(err, "failed to print version")
			}
			return nil
		},
	}
	return cmd
}
