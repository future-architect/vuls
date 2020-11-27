package main

import (
	"flag"
	"fmt"
	"os"

	"context"

	"github.com/future-architect/vuls/config"
	commands "github.com/future-architect/vuls/subcmds"
	"github.com/google/subcommands"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&commands.DiscoverCmd{}, "discover")
	subcommands.Register(&commands.ScanCmd{}, "scan")
	subcommands.Register(&commands.HistoryCmd{}, "history")
	subcommands.Register(&commands.ConfigtestCmd{}, "configtest")

	var v = flag.Bool("v", false, "Show version")

	flag.Parse()

	if *v {
		fmt.Printf("vuls %s %s\n", config.Version, config.Revision)
		os.Exit(int(subcommands.ExitSuccess))
	}

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
