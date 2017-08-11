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

package commands

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/report"
	"github.com/google/subcommands"
)

// HistoryCmd is Subcommand of list scanned results
type HistoryCmd struct {
	debug      bool
	debugSQL   bool
	resultsDir string
}

// Name return subcommand name
func (*HistoryCmd) Name() string { return "history" }

// Synopsis return synopsis
func (*HistoryCmd) Synopsis() string {
	return `List history of scanning.`
}

// Usage return usage
func (*HistoryCmd) Usage() string {
	return `history:
	history
		[-results-dir=/path/to/results]
	`
}

// SetFlags set flag
func (p *HistoryCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()
	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")
}

// Execute execute
func (p *HistoryCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.DebugSQL = p.debugSQL
	c.Conf.ResultsDir = p.resultsDir

	dirs, err := report.ListValidJSONDirs()
	if err != nil {
		return subcommands.ExitFailure
	}
	for _, d := range dirs {
		var files []os.FileInfo
		if files, err = ioutil.ReadDir(d); err != nil {
			return subcommands.ExitFailure
		}
		var hosts []string
		for _, f := range files {
			if filepath.Ext(f.Name()) != ".json" {
				continue
			}
			fileBase := strings.TrimSuffix(f.Name(), filepath.Ext(f.Name()))
			hosts = append(hosts, fileBase)
		}
		splitPath := strings.Split(d, string(os.PathSeparator))
		timeStr := splitPath[len(splitPath)-1]
		fmt.Printf("%s %d servers: %s\n",
			timeStr,
			len(hosts),
			strings.Join(hosts, ", "),
		)
	}
	return subcommands.ExitSuccess
}
