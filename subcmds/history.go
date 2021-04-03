package subcmds

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/reporter"
	"github.com/google/subcommands"
)

// HistoryCmd is Subcommand of list scanned results
type HistoryCmd struct{}

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
	f.BoolVar(&config.Conf.DebugSQL, "debug-sql", false, "SQL debug mode")

	wd, _ := os.Getwd()
	defaultResultsDir := filepath.Join(wd, "results")
	f.StringVar(&config.Conf.ResultsDir, "results-dir", defaultResultsDir, "/path/to/results")
}

// Execute execute
func (p *HistoryCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	dirs, err := reporter.ListValidJSONDirs(config.Conf.ResultsDir)
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
