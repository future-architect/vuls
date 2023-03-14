package v1

import (
	"encoding/json"
	"os"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

// SNMPv1Options ...
type SNMPv1Options struct {
	Debug bool
}

// NewCmdV1 ...
func NewCmdV1() *cobra.Command {
	opts := &SNMPv1Options{
		Debug: false,
	}

	cmd := &cobra.Command{
		Use:     "v1 <IP Address> <Community>",
		Short:   "snmpget with SNMPv1",
		Example: "$ snmp2cpe v1 192.168.100.1 public",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := snmp.Get(gosnmp.Version1, args[0], snmp.WithCommunity(args[1]), snmp.WithDebug(opts.Debug))
			if err != nil {
				return errors.Wrap(err, "failed to snmpget")
			}

			if err := json.NewEncoder(os.Stdout).Encode(map[string]snmp.Result{args[0]: r}); err != nil {
				return errors.Wrap(err, "failed to encode")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&opts.Debug, "debug", "", false, "debug mode")

	return cmd
}
