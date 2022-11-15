package search

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdSearch() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "search",
		Short: "Search Vulnerabilty/Package in Vuls DB",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls db search ubuntu 22.04 openssl
			$ vuls db search vulnerability CVE-2022-3602
		`),
	}

	return cmd
}
