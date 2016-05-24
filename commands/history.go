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
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/context"

	"github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/db"
	"github.com/future-architect/vuls/models"
	"github.com/google/subcommands"
)

// HistoryCmd is Subcommand of list scanned results
type HistoryCmd struct {
	debug    bool
	debugSQL bool

	dbpath string
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
		[-dbpath=/path/to/vuls.sqlite3]
	`
}

// SetFlags set flag
func (p *HistoryCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&p.debugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()
	defaultDBPath := filepath.Join(wd, "vuls.sqlite3")
	f.StringVar(&p.dbpath, "dbpath", defaultDBPath, "/path/to/sqlite3")
}

// Execute execute
func (p *HistoryCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {

	c.Conf.DebugSQL = p.debugSQL
	c.Conf.DBPath = p.dbpath

	//  _, err := scanHistories()
	histories, err := scanHistories()
	if err != nil {
		logrus.Error("Failed to select scan histories: ", err)
		return subcommands.ExitFailure
	}
	const timeLayout = "2006-01-02 15:04"
	for _, history := range histories {
		names := []string{}
		for _, result := range history.ScanResults {
			if 0 < len(result.Container.ContainerID) {
				names = append(names, result.Container.Name)
			} else {
				names = append(names, result.ServerName)
			}
		}
		fmt.Printf("%-3d %s scanned %d servers: %s\n",
			history.ID,
			history.ScannedAt.Format(timeLayout),
			len(history.ScanResults),
			strings.Join(names, ", "),
		)
	}
	return subcommands.ExitSuccess
}

func scanHistories() (histories []models.ScanHistory, err error) {
	if err := db.OpenDB(); err != nil {
		return histories, fmt.Errorf(
			"Failed to open DB. datafile: %s, err: %s", c.Conf.DBPath, err)
	}
	histories, err = db.SelectScanHistories()
	return
}
