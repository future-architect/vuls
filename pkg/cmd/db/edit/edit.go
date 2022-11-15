package edit

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdEdit() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Edit Data in Vuls DB",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls db edit ubuntu 22.04 openssl
			$ vuls db edit vulnerability CVE-2022-3602
		`),
	}

	return cmd
}
