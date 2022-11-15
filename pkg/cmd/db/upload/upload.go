package upload

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

func NewCmdUpload() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload Vuls DB",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls db upload
			$ vuls db upload ghcr.io/vuls/db
		`),
	}

	return cmd
}
