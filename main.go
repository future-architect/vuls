/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/net/context"

	"github.com/future-architect/vuls/commands"
	"github.com/future-architect/vuls/version"
	"github.com/google/subcommands"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	subcommands.Register(subcommands.HelpCommand(), "")
	subcommands.Register(subcommands.FlagsCommand(), "")
	subcommands.Register(subcommands.CommandsCommand(), "")
	subcommands.Register(&commands.DiscoverCmd{}, "discover")
	subcommands.Register(&commands.TuiCmd{}, "tui")
	subcommands.Register(&commands.ScanCmd{}, "scan")
	subcommands.Register(&commands.PrepareCmd{}, "prepare")
	subcommands.Register(&commands.HistoryCmd{}, "history")
	subcommands.Register(&commands.ConfigtestCmd{}, "configtest")

	var v = flag.Bool("v", false, "Show version")

	flag.Parse()

	if *v {
		fmt.Printf("%s %s\n", version.Name, version.Version)
		os.Exit(int(subcommands.ExitSuccess))
	}

	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
