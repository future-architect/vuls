package v2c

import (
	"encoding/json"
	"os"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

// SNMPv2cOptions ...
type SNMPv2cOptions struct {
	Port  uint16
	Debug bool
}

// NewCmdV2c ...
func NewCmdV2c() *cobra.Command {
	opts := &SNMPv2cOptions{
		Port:  161,
		Debug: false,
	}

	cmd := &cobra.Command{
		Use:     "v2c <IP Address> <Community>",
		Short:   "snmpget with SNMPv2c",
		Example: "$ snmp2cpe v2c 192.168.100.1 public",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := snmp.Get(gosnmp.Version2c, args[0], snmp.WithCommunity(args[1]), snmp.WithPort(opts.Port), snmp.WithDebug(opts.Debug))
			if err != nil {
				return errors.Wrap(err, "failed to snmpget")
			}

			if err := json.NewEncoder(os.Stdout).Encode(map[string]snmp.Result{args[0]: r}); err != nil {
				return errors.Wrap(err, "failed to encode")
			}

			return nil
		},
	}

	cmd.Flags().Uint16VarP(&opts.Port, "port", "P", 161, "port")
	cmd.Flags().BoolVarP(&opts.Debug, "debug", "", false, "debug mode")

	return cmd
}
