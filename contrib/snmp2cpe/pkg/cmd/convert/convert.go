package convert

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/cpe"
	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

// NewCmdConvert ...
func NewCmdConvert() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "convert",
		Short: "snmpget reply to CPE",
		Args:  cobra.MaximumNArgs(1),
		Example: `$ snmp2cpe v2c 192.168.11.11 public | snmp2cpe convert
$ snmp2cpe v2c 192.168.11.11 public | snmp2cpe convert -
$ snmp2cpe v2c 192.168.11.11 public > v2c.json && snmp2cpe convert v2c.json`,
		RunE: func(_ *cobra.Command, args []string) error {
			r := os.Stdin
			if len(args) == 1 && args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					return errors.Wrapf(err, "failed to open %s", args[0])
				}
				defer f.Close()
				r = f
			}

			var reply map[string]snmp.Result
			if err := json.NewDecoder(r).Decode(&reply); err != nil {
				return errors.Wrap(err, "failed to decode")
			}

			converted := map[string][]string{}
			for ipaddr, res := range reply {
				converted[ipaddr] = cpe.Convert(res)
			}

			if err := json.NewEncoder(os.Stdout).Encode(converted); err != nil {
				return errors.Wrap(err, "failed to encode")
			}

			return nil
		},
	}
	return cmd
}
