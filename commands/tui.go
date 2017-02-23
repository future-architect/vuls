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
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/Sirupsen/logrus"
	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/google/subcommands"
	"github.com/peco/peco"
)

// TuiCmd is Subcommand of host discovery mode
type TuiCmd struct {
	lang       string
	debugSQL   bool
	resultsDir string

	refreshCve       bool
	cvedbtype        string
	cvedbpath        string
	cveDictionaryURL string
}

// Name return subcommand name
func (*TuiCmd) Name() string { return "tui" }

// Synopsis return synopsis
func (*TuiCmd) Synopsis() string { return "Run Tui view to anayze vulnerabilites" }

// Usage return usage
func (*TuiCmd) Usage() string {
	return `tui:
	tui
		[-cvedb-type=sqlite3|mysql]
		[-cvedb-path=/path/to/cve.sqlite3]
		[-cvedb-url=http://127.0.0.1:1323 or mysql connection string]
		[-results-dir=/path/to/results]
		[-refresh-cve]
		[-debug-sql]
`
}

// SetFlags set flag
func (p *TuiCmd) SetFlags(f *flag.FlagSet) {
	//  f.StringVar(&p.lang, "lang", "en", "[en|ja]")
	f.BoolVar(&p.debugSQL, "debug-sql", false, "debug SQL")

	wd, _ := os.Getwd()
	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&p.resultsDir, "results-dir", defaultResultsDir, "/path/to/results")

	f.BoolVar(
		&p.refreshCve,
		"refresh-cve",
		false,
		"Refresh CVE information in JSON file under results dir")

	f.StringVar(
		&p.cvedbtype,
		"cvedb-type",
		"sqlite3",
		"DB type for fetching CVE dictionary (sqlite3 or mysql)")

	defaultCveDBPath := filepath.Join(wd, "cve.sqlite3")
	f.StringVar(
		&p.cvedbpath,
		"cvedb-path",
		defaultCveDBPath,
		"/path/to/sqlite3 (For get cve detail from cve.sqlite3)")

	f.StringVar(
		&p.cveDictionaryURL,
		"cvedb-url",
		"",
		"http://cve-dictionary.com:8080 or mysql connection string")
}

// TODO README, test, glide.lock, glide.yaml

// Execute execute
func (p *TuiCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	c.Conf.Lang = "en"
	c.Conf.DebugSQL = p.debugSQL
	c.Conf.ResultsDir = p.resultsDir
	c.Conf.CveDBType = p.cvedbtype
	c.Conf.CveDBPath = p.cvedbpath
	c.Conf.CveDictionaryURL = p.cveDictionaryURL

	log.Info("Validating config...")
	if !c.Conf.ValidateOnTui() {
		return subcommands.ExitUsageError
	}

	list, err := scanList()
	if err != nil {
		log.Errorf("Failed to list scan history: %s", err)
		return subcommands.ExitFailure
	}

	var buf bytes.Buffer
	ctx := context.Background()
	cli := peco.New()
	cli.Stdin = strings.NewReader(strings.Join(list, "\n"))
	cli.Stdout = &buf
	cli.Argv = []string{}
	cli.Run(ctx)
	cli.PrintResults()

	timeDir := strings.Split(buf.String(), " ")[0]
	if timeDir == "" {
		log.Error("Failed to filter by peco")
		return subcommands.ExitFailure
	}

	jsonDir := filepath.Join(c.Conf.ResultsDir, timeDir)
	history, err := loadOneScanHistory(jsonDir)
	if err != nil {
		log.Errorf("Failed to read from JSON: %s", err)
		return subcommands.ExitFailure
	}

	var results []models.ScanResult
	for _, r := range history.ScanResults {
		if p.refreshCve || needToRefreshCve(r) {
			if c.Conf.CveDBType == "sqlite3" {
				if _, err := os.Stat(c.Conf.CveDBPath); os.IsNotExist(err) {
					log.Errorf("SQLite3 DB(CVE-Dictionary) is not exist: %s",
						c.Conf.CveDBPath)
					return subcommands.ExitFailure
				}
			}

			filled, err := fillCveInfoFromCveDB(r)
			if err != nil {
				log.Errorf("Failed to fill CVE information: %s", err)
				return subcommands.ExitFailure
			}

			if err := overwriteJSONFile(jsonDir, filled); err != nil {
				log.Errorf("Failed to write JSON: %s", err)
				return subcommands.ExitFailure
			}
			results = append(results, filled)
		} else {
			results = append(results, r)
		}
	}
	history.ScanResults = results
	return report.RunTui(history)
}

func scanList() (lines []string, err error) {
	var dirs jsonDirs
	if dirs, err = lsValidJSONDirs(); err != nil {
		return nil, err
	}

	for _, d := range dirs {
		var files []os.FileInfo
		if files, err = ioutil.ReadDir(d); err != nil {
			return nil, err
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
		lines = append(lines, fmt.Sprintf("%s %d servers: %s",
			timeStr, len(hosts), strings.Join(hosts, ", ")))
	}
	return
}
