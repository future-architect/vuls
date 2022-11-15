package tui

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

type TUIOptions struct {
	Config string
}

func NewCmdTUI() *cobra.Command {
	opts := &TUIOptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "tui (<result path>)",
		Short: "View vulnerabilities detected by TUI",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls tui
			$ vuls tui results
			$ vuls tui resutls/2022-11-05T01:08:44+09:00/local/localhost.json
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}
