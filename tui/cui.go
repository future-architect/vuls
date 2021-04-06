package tui

import (
	"github.com/future-architect/vuls/models"
	"github.com/google/subcommands"
	"github.com/rivo/tview"
)

// RunCui execute main logic
func RunCui(results models.ScanResults) subcommands.ExitStatus {
	box := tview.NewBox().SetBorder(true).SetTitle("Hello, world!")
	if err := tview.NewApplication().SetRoot(box, true).Run(); err != nil {
		panic(err)
	}
	return subcommands.ExitSuccess
}
