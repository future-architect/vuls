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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/report"
	"github.com/google/subcommands"
)

// TuiCmd is Subcommand of host discovery mode
type TuiCmd struct {
	lang       string
	debugSQL   bool
	resultsDir string
}

// Name return subcommand name
func (*TuiCmd) Name() string { return "tui" }

// Synopsis return synopsis
func (*TuiCmd) Synopsis() string { return "Run Tui view to anayze vulnerabilites" }

// Usage return usage
func (*TuiCmd) Usage() string {
	return `tui:
	tui [-results-dir=/path/to/results]

`
}

// SetFlags set flag
func (p *TuiCmd) SetFlags(f *flag.FlagSet) {
	//  f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "debug SQL")

	wd, _ := os.Getwd()

	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")
}

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Lang = "en"
	c.Conf.DebugSQL = p.debugSQL
	c.Conf.ResultsDir = p.resultsDir

	var jsonDirName string
	var err error
	if 0 < len(f.Args()) {
		var jsonDirs report.JSONDirs
		if jsonDirs, err = report.GetValidJSONDirs(); err != nil {
			return subcommands.ExitFailure
		}
		for _, d := range jsonDirs {
			splitPath := strings.Split(d, string(os.PathSeparator))
			if splitPath[len(splitPath)-1] == f.Args()[0] {
				jsonDirName = f.Args()[0]
				break
			}
		}
		if len(jsonDirName) == 0 {
			log.Errorf("First Argument have to be JSON directory name : %s", err)
			return subcommands.ExitFailure
		}
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			bytes, err := ioutil.ReadAll(os.Stdin)
			if err != nil {
				log.Errorf("Failed to read stdin: %s", err)
				return subcommands.ExitFailure
			}
			fields := strings.Fields(string(bytes))
			if 0 < len(fields) {
				jsonDirName = fields[0]
			}
		}
	}
	return report.RunTui(jsonDirName)
}
