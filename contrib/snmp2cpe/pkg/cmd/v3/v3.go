package v3

import (
	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

// SNMPv3Options ...
type SNMPv3Options struct {
	Port  uint16
	Debug bool
}

// NewCmdV3 ...
func NewCmdV3() *cobra.Command {
	opts := &SNMPv3Options{
		Port:  161,
		Debug: false,
	}

	cmd := &cobra.Command{
		Use:     "v3 <args>",
		Short:   "snmpget with SNMPv3",
		Example: "$ snmp2cpe v3",
		RunE: func(_ *cobra.Command, _ []string) error {
			_, err := snmp.Get(gosnmp.Version3, "", snmp.WithPort(opts.Port), snmp.WithDebug(opts.Debug))
			if err != nil {
				return errors.Wrap(err, "failed to snmpget")
			}

			return nil
		},
	}

	cmd.Flags().Uint16VarP(&opts.Port, "port", "P", 161, "port")
	cmd.Flags().BoolVarP(&opts.Debug, "debug", "", false, "debug mode")

	return cmd
}
