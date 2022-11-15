package config

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	configInitCmd "github.com/future-architect/vuls/pkg/cmd/config/init"
)

func NewCmdConfig() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config <subcommand>",
		Short: "Vuls Config Operation",
		Example: heredoc.Doc(`
			$ vuls config init > config.json
		`),
	}

	cmd.AddCommand(configInitCmd.NewCmdInit())

	return cmd
}
