package root

import (
	"github.com/spf13/cobra"

	convertCmd "github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cmd/convert"
	v1Cmd "github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cmd/v1"
	v2cCmd "github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cmd/v2c"
	v3Cmd "github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cmd/v3"
	versionCmd "github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cmd/version"
)

// NewCmdRoot ...
func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "snmp2cpe <command>",
		Short:         "snmp2cpe",
		Long:          "snmp2cpe: SNMP reply To CPE",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.AddCommand(v1Cmd.NewCmdV1())
	cmd.AddCommand(v2cCmd.NewCmdV2c())
	cmd.AddCommand(v3Cmd.NewCmdV3())
	cmd.AddCommand(convertCmd.NewCmdConvert())
	cmd.AddCommand(versionCmd.NewCmdVersion())

	return cmd
}
