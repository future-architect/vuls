package db

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	dbCreateCmd "github.com/future-architect/vuls/pkg/cmd/db/create"
	dbEditCmd "github.com/future-architect/vuls/pkg/cmd/db/edit"
	dbFetchCmd "github.com/future-architect/vuls/pkg/cmd/db/fetch"
	dbSearchCmd "github.com/future-architect/vuls/pkg/cmd/db/search"
	dbUploadCmd "github.com/future-architect/vuls/pkg/cmd/db/upload"
)

func NewCmdDB() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db <subcommand>",
		Short: "Vuls DB Operation",
		Example: heredoc.Doc(`
			$ vuls db create https://github.com/vulsio/vuls-data.git
			$ vuls db create /home/MaineK00n/.cache/vuls
			$ vuls db edit ubuntu 22.04 openssl
			$ vuls db edit vulnerability CVE-2022-3602
			$ vuls db fetch
			$ vuls db fetch ghcr.io/vuls/db
			$ vuls db search ubuntu 22.04 openssl
			$ vuls db search vulnerability CVE-2022-3602
		`),
	}

	cmd.AddCommand(dbCreateCmd.NewCmdCreate())
	cmd.AddCommand(dbEditCmd.NewCmdEdit())
	cmd.AddCommand(dbFetchCmd.NewCmdFetch())
	cmd.AddCommand(dbSearchCmd.NewCmdSearch())
	cmd.AddCommand(dbUploadCmd.NewCmdUpload())

	return cmd
}
