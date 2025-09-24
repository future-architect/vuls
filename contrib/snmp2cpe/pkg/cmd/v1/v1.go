package v1

import (
	"encoding/json"
	"os"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/future-architect/vuls/contrib/snmp2cpe/pkg/snmp"
)

// SNMPv1Options ...
type SNMPv1Options struct {
	Port    uint16
	Timeout time.Duration
	Retry   int
	Debug   bool
}

// NewCmdV1 ...
func NewCmdV1() *cobra.Command {
	opts := &SNMPv1Options{
		Port:    161,
		Timeout: time.Duration(2) * time.Second,
		Retry:   3,
		Debug:   false,
	}

	cmd := &cobra.Command{
		Use:     "v1 <IP Address> <Community>",
		Short:   "snmpget with SNMPv1",
		Example: "$ snmp2cpe v1 192.168.100.1 public",
		Args:    cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := snmp.Get(gosnmp.Version1, args[0], snmp.WithCommunity(args[1]), snmp.WithPort(opts.Port), snmp.WithTimeout(opts.Timeout), snmp.WithRetry(opts.Retry), snmp.WithDebug(opts.Debug))
			if err != nil {
				return errors.Wrap(err, "failed to snmpget")
			}

			if err := json.NewEncoder(os.Stdout).Encode(map[string]snmp.Result{args[0]: r}); err != nil {
				return errors.Wrap(err, "failed to encode")
			}

			return nil
		},
	}

	cmd.Flags().Uint16VarP(&opts.Port, "port", "P", opts.Port, "port")
	cmd.Flags().DurationVarP(&opts.Timeout, "timeout", "t", opts.Timeout, "timeout")
	cmd.Flags().IntVarP(&opts.Retry, "retry", "r", opts.Retry, "retry")
	cmd.Flags().BoolVarP(&opts.Debug, "debug", "", opts.Debug, "debug mode")

	return cmd
}
