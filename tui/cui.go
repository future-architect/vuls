package tui

import (
	"sort"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/google/subcommands"
	"github.com/rivo/tview"
)

// RunCui execute main logic
func RunCui(results models.ScanResults) subcommands.ExitStatus {
	scanResults = results
	sort.Slice(scanResults, func(i, j int) bool {
		if scanResults[i].ServerName == scanResults[j].ServerName {
			return scanResults[i].Container.Name < scanResults[j].Container.Name
		}
		return scanResults[i].ServerName < scanResults[j].ServerName
	})

	app := tview.NewApplication()
	flex := tview.NewFlex().
		AddItem(tview.NewFlex().SetDirection(tview.FlexRow).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(tview.NewBox().SetBorder(true).SetTitle("Target"), 20, 1, false).
				AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
					AddItem(tview.NewBox().SetBorder(true).SetTitle("Summary"), 0, 1, false), 0, 1, false), 0, 1, false).
			AddItem(tview.NewFlex().SetDirection(tview.FlexColumn).
				AddItem(tview.NewBox().SetBorder(true).SetTitle("Details"), 0, 1, false), 0, 1, false), 0, 1, false)
	if err := app.SetRoot(flex, true).SetFocus(flex).Run(); err != nil {
		logging.Log.Errorf("%+v", err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}
