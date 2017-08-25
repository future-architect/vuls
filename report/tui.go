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

package report

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/google/subcommands"
	"github.com/gosuri/uitable"
	"github.com/jroimartin/gocui"
	log "github.com/sirupsen/logrus"
)

var scanResults models.ScanResults
var currentScanResult models.ScanResult
var vinfos []models.VulnInfo
var currentVinfo int
var currentDetailLimitY int
var currentChangelogLimitY int

// RunTui execute main logic
func RunTui(results models.ScanResults) subcommands.ExitStatus {
	scanResults = results

	// g, err := gocui.NewGui(gocui.OutputNormal)
	g := gocui.NewGui()
	if err := g.Init(); err != nil {
		log.Errorf("%s", err)
		return subcommands.ExitFailure
	}
	defer g.Close()

	g.SetLayout(layout)
	// g.SetManagerFunc(layout)
	if err := keybindings(g); err != nil {
		log.Errorf("%s", err)
		return subcommands.ExitFailure
	}
	g.SelBgColor = gocui.ColorGreen
	g.SelFgColor = gocui.ColorBlack
	g.Cursor = true

	if err := g.MainLoop(); err != nil {
		g.Close()
		log.Errorf("%s", err)
		os.Exit(1)
	}
	return subcommands.ExitSuccess
}

func keybindings(g *gocui.Gui) (err error) {
	errs := []error{}

	// Move beetween views
	errs = append(errs, g.SetKeybinding("side", gocui.KeyTab, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlH, gocui.ModNone, previousView))
	//  errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlL, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("side", gocui.KeyArrowRight, gocui.ModAlt, nextView))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyArrowDown, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlJ, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyArrowUp, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlK, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlD, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlU, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("side", gocui.KeySpace, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyBackspace, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyBackspace2, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlN, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyCtrlP, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("side", gocui.KeyEnter, gocui.ModNone, nextView))

	//  errs = append(errs, g.SetKeybinding("msg", gocui.KeyEnter, gocui.ModNone, delMsg))
	//  errs = append(errs, g.SetKeybinding("side", gocui.KeyEnter, gocui.ModNone, showMsg))

	// summary
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyTab, gocui.ModNone, nextView))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlQ, gocui.ModNone, previousView))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlH, gocui.ModNone, previousView))
	//  errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlL, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("summary", gocui.KeyArrowLeft, gocui.ModAlt, previousView))
	//  errs = append(errs, g.SetKeybinding("summary", gocui.KeyArrowDown, gocui.ModAlt, nextView))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyArrowDown, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyArrowUp, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlJ, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlK, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlD, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlU, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeySpace, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyBackspace, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyBackspace2, gocui.ModNone, cursorPageUp))
	//  errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlM, gocui.ModNone, cursorMoveMiddle))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyEnter, gocui.ModNone, nextView))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlN, gocui.ModNone, nextSummary))
	errs = append(errs, g.SetKeybinding("summary", gocui.KeyCtrlP, gocui.ModNone, previousSummary))

	// detail
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyTab, gocui.ModNone, nextView))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlQ, gocui.ModNone, previousView))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlH, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlL, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("detail", gocui.KeyArrowUp, gocui.ModAlt, previousView))
	//  errs = append(errs, g.SetKeybinding("detail", gocui.KeyArrowLeft, gocui.ModAlt, nextView))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyArrowDown, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyArrowUp, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlJ, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlK, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlD, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlU, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeySpace, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyBackspace, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyBackspace2, gocui.ModNone, cursorPageUp))
	//  errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlM, gocui.ModNone, cursorMoveMiddle))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlN, gocui.ModNone, nextSummary))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyCtrlP, gocui.ModNone, previousSummary))
	errs = append(errs, g.SetKeybinding("detail", gocui.KeyEnter, gocui.ModNone, nextView))

	// changelog
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyTab, gocui.ModNone, nextView))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlQ, gocui.ModNone, previousView))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlH, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlL, gocui.ModNone, nextView))
	//  errs = append(errs, g.SetKeybinding("changelog", gocui.KeyArrowUp, gocui.ModAlt, previousView))
	//  errs = append(errs, g.SetKeybinding("changelog", gocui.KeyArrowLeft, gocui.ModAlt, nextView))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyArrowDown, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyArrowUp, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlJ, gocui.ModNone, cursorDown))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlK, gocui.ModNone, cursorUp))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlD, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlU, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeySpace, gocui.ModNone, cursorPageDown))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyBackspace, gocui.ModNone, cursorPageUp))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyBackspace2, gocui.ModNone, cursorPageUp))
	//  errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlM, gocui.ModNone, cursorMoveMiddle))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlN, gocui.ModNone, nextSummary))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyCtrlP, gocui.ModNone, previousSummary))
	errs = append(errs, g.SetKeybinding("changelog", gocui.KeyEnter, gocui.ModNone, nextView))

	//  errs = append(errs, g.SetKeybinding("msg", gocui.KeyEnter, gocui.ModNone, delMsg))
	//  errs = append(errs, g.SetKeybinding("detail", gocui.KeyEnter, gocui.ModNone, showMsg))

	//TODO Help Ctrl-h

	errs = append(errs, g.SetKeybinding("", gocui.KeyCtrlC, gocui.ModNone, quit))
	//  errs = append(errs, g.SetKeybinding("side", gocui.KeyEnter, gocui.ModNone, getLine))
	//  errs = append(errs, g.SetKeybinding("msg", gocui.KeyEnter, gocui.ModNone, delMsg))

	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func nextView(g *gocui.Gui, v *gocui.View) error {
	var err error

	if v == nil {
		err = g.SetCurrentView("side")
	}
	switch v.Name() {
	case "side":
		err = g.SetCurrentView("summary")
	case "summary":
		err = g.SetCurrentView("detail")
	case "detail":
		err = g.SetCurrentView("changelog")
	case "changelog":
		err = g.SetCurrentView("side")
	default:
		err = g.SetCurrentView("summary")
	}
	return err
}

func previousView(g *gocui.Gui, v *gocui.View) error {
	var err error

	if v == nil {
		err = g.SetCurrentView("side")
	}
	switch v.Name() {
	case "side":
		err = g.SetCurrentView("side")
	case "summary":
		err = g.SetCurrentView("side")
	case "detail":
		err = g.SetCurrentView("summary")
	case "changelog":
		err = g.SetCurrentView("detail")
	default:
		err = g.SetCurrentView("side")
	}
	return err
}

func movable(v *gocui.View, nextY int) (ok bool, yLimit int) {
	switch v.Name() {
	case "side":
		yLimit = len(scanResults) - 1
		if yLimit < nextY {
			return false, yLimit
		}
		return true, yLimit
	case "summary":
		yLimit = len(currentScanResult.ScannedCves) - 1
		if yLimit < nextY {
			return false, yLimit
		}
		return true, yLimit
	case "detail":
		// if currentDetailLimitY < nextY {
		// return false, currentDetailLimitY
		// }
		return true, currentDetailLimitY
	case "changelog":
		// if currentChangelogLimitY < nextY {
		// return false, currentChangelogLimitY
		// }
		return true, currentChangelogLimitY
	default:
		return true, 0
	}
}

func pageUpDownJumpCount(v *gocui.View) int {
	var jump int
	switch v.Name() {
	case "side", "summary":
		jump = 8
	case "detail", "changelog":
		jump = 30
	default:
		jump = 8
	}
	return jump
}

// redraw views
func onMovingCursorRedrawView(g *gocui.Gui, v *gocui.View) error {
	switch v.Name() {
	case "summary":
		if err := redrawDetail(g); err != nil {
			return err
		}
		if err := redrawChangelog(g); err != nil {
			return err
		}
	case "side":
		if err := changeHost(g, v); err != nil {
			return err
		}
	}
	return nil
}

func cursorDown(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		cx, cy := v.Cursor()
		ox, oy := v.Origin()
		//  ok,  := movable(v, oy+cy+1)
		//  _, maxY := v.Size()
		ok, _ := movable(v, oy+cy+1)
		//  log.Info(cy, oy)
		if !ok {
			return nil
		}
		if err := v.SetCursor(cx, cy+1); err != nil {
			if err := v.SetOrigin(ox, oy+1); err != nil {
				return err
			}
		}
		onMovingCursorRedrawView(g, v)
	}

	cx, cy := v.Cursor()
	ox, oy := v.Origin()
	debug(g, fmt.Sprintf("%v, %v, %v, %v", cx, cy, ox, oy))
	return nil
}

func cursorMoveTop(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		cx, _ := v.Cursor()
		v.SetCursor(cx, 0)
	}
	onMovingCursorRedrawView(g, v)
	return nil
}

func cursorMoveBottom(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, maxY := v.Size()
		cx, _ := v.Cursor()
		v.SetCursor(cx, maxY-1)
	}
	onMovingCursorRedrawView(g, v)
	return nil
}

func cursorMoveMiddle(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		_, maxY := v.Size()
		cx, _ := v.Cursor()
		v.SetCursor(cx, maxY/2)
	}
	onMovingCursorRedrawView(g, v)
	return nil
}

func cursorPageDown(g *gocui.Gui, v *gocui.View) error {
	jump := pageUpDownJumpCount(v)

	if v != nil {
		cx, cy := v.Cursor()
		ox, oy := v.Origin()
		ok, yLimit := movable(v, oy+cy+jump)
		_, maxY := v.Size()

		if !ok {
			if yLimit < maxY {
				v.SetCursor(cx, yLimit)
			} else {
				v.SetCursor(cx, maxY-1)
				v.SetOrigin(ox, yLimit-maxY+1)
			}
		} else if yLimit < oy+jump+maxY {
			if yLimit < maxY {
				v.SetCursor(cx, yLimit)
			} else {
				v.SetOrigin(ox, yLimit-maxY+1)
				v.SetCursor(cx, maxY-1)
			}
		} else {
			v.SetCursor(cx, cy)
			v.SetOrigin(ox, oy+jump)
		}
		onMovingCursorRedrawView(g, v)
	}
	return nil
}

func cursorUp(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		ox, oy := v.Origin()
		cx, cy := v.Cursor()
		if err := v.SetCursor(cx, cy-1); err != nil && 0 < oy {
			if err := v.SetOrigin(ox, oy-1); err != nil {
				return err
			}
		}
	}
	onMovingCursorRedrawView(g, v)
	return nil
}

func cursorPageUp(g *gocui.Gui, v *gocui.View) error {
	jump := pageUpDownJumpCount(v)
	if v != nil {
		cx, _ := v.Cursor()
		ox, oy := v.Origin()
		if err := v.SetOrigin(ox, oy-jump); err != nil {
			v.SetOrigin(ox, 0)
			v.SetCursor(cx, 0)

		}
		onMovingCursorRedrawView(g, v)
	}
	return nil
}

func previousSummary(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		// cursor to summary
		if err := g.SetCurrentView("summary"); err != nil {
			return err
		}
		// move next line
		if err := cursorUp(g, g.CurrentView()); err != nil {
			return err
		}
		// cursor to detail
		if err := g.SetCurrentView("detail"); err != nil {
			return err
		}
	}
	return nil
}

func nextSummary(g *gocui.Gui, v *gocui.View) error {
	if v != nil {
		// cursor to summary
		if err := g.SetCurrentView("summary"); err != nil {
			return err
		}
		// move next line
		if err := cursorDown(g, g.CurrentView()); err != nil {
			return err
		}
		// cursor to detail
		if err := g.SetCurrentView("detail"); err != nil {
			return err
		}
	}
	return nil
}

func changeHost(g *gocui.Gui, v *gocui.View) error {

	if err := g.DeleteView("summary"); err != nil {
		return err
	}
	if err := g.DeleteView("detail"); err != nil {
		return err
	}
	if err := g.DeleteView("changelog"); err != nil {
		return err
	}

	_, cy := v.Cursor()
	l, err := v.Line(cy)
	if err != nil {
		return err
	}
	serverName := strings.TrimSpace(l)

	for _, r := range scanResults {
		if serverName == strings.TrimSpace(r.ServerInfoTui()) {
			currentScanResult = r
			vinfos = r.ScannedCves.ToSortedSlice()
			break
		}
	}

	if err := setSummaryLayout(g); err != nil {
		return err
	}
	if err := setDetailLayout(g); err != nil {
		return err
	}
	if err := setChangelogLayout(g); err != nil {
		return err
	}
	return nil
}

func redrawDetail(g *gocui.Gui) error {
	if err := g.DeleteView("detail"); err != nil {
		return err
	}

	if err := setDetailLayout(g); err != nil {
		return err
	}
	return nil
}

func redrawChangelog(g *gocui.Gui) error {
	if err := g.DeleteView("changelog"); err != nil {
		return err
	}

	if err := setChangelogLayout(g); err != nil {
		return err
	}
	return nil
}

func getLine(g *gocui.Gui, v *gocui.View) error {
	var l string
	var err error

	_, cy := v.Cursor()
	if l, err = v.Line(cy); err != nil {
		l = ""
	}

	maxX, maxY := g.Size()
	if v, err := g.SetView("msg", maxX/2-30, maxY/2, maxX/2+30, maxY/2+2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		fmt.Fprintln(v, l)
		if err := g.SetCurrentView("msg"); err != nil {
			return err
		}
	}
	return nil
}

func showMsg(g *gocui.Gui, v *gocui.View) error {
	jump := 8
	_, cy := v.Cursor()
	_, oy := v.Origin()
	ok, yLimit := movable(v, oy+cy+jump)
	//  maxX, maxY := v.Size()
	_, maxY := v.Size()

	l := fmt.Sprintf("cy: %d, oy: %d, maxY: %d, yLimit: %d, curCve %d, ok: %v",
		cy, oy, maxY, yLimit, currentVinfo, ok)
	//  if v, err := g.SetView("msg", maxX/2-30, maxY/2, maxX/2+30, maxY/2+2); err != nil {
	if v, err := g.SetView("msg", 10, maxY/2, 10+50, maxY/2+2); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		fmt.Fprintln(v, l)
		if err := g.SetCurrentView("msg"); err != nil {
			return err
		}
	}
	return nil
}

func delMsg(g *gocui.Gui, v *gocui.View) error {
	if err := g.DeleteView("msg"); err != nil {
		return err
	}
	if err := g.SetCurrentView("summary"); err != nil {
		return err
	}
	return nil
}

func quit(g *gocui.Gui, v *gocui.View) error {
	return gocui.ErrQuit
}

func layout(g *gocui.Gui) error {
	if err := setSideLayout(g); err != nil {
		return err
	}
	if err := setSummaryLayout(g); err != nil {
		return err
	}
	if err := setDetailLayout(g); err != nil {
		return err
	}
	if err := setChangelogLayout(g); err != nil {
		return err
	}

	return nil
}

func debug(g *gocui.Gui, str string) error {
	if config.Conf.Debug {
		maxX, maxY := g.Size()
		if _, err := g.View("debug"); err != gocui.ErrUnknownView {
			g.DeleteView("debug")
		}
		if v, err := g.SetView("debug", maxX/2-7, maxY/2, maxX/2+7, maxY/2+2); err != nil {
			fmt.Fprintf(v, str)
		}
	}
	return nil
}

func setSideLayout(g *gocui.Gui) error {
	_, maxY := g.Size()
	if v, err := g.SetView("side", -1, -1, 40, int(float64(maxY)*0.2)); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		v.Highlight = true

		for _, result := range scanResults {
			fmt.Fprintln(v, result.ServerInfoTui())
		}
		if len(scanResults) == 0 {
			return fmt.Errorf("No scan results")
		}
		currentScanResult = scanResults[0]
		vinfos = scanResults[0].ScannedCves.ToSortedSlice()
		if err := g.SetCurrentView("side"); err != nil {
			return err
		}
	}
	return nil
}

func setSummaryLayout(g *gocui.Gui) error {
	maxX, maxY := g.Size()
	if v, err := g.SetView("summary", 40, -1, maxX, int(float64(maxY)*0.2)); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}

		lines := summaryLines()
		fmt.Fprintf(v, lines)

		v.Highlight = true
		v.Editable = false
		v.Wrap = false
	}
	return nil
}

func summaryLines() string {
	stable := uitable.New()
	stable.MaxColWidth = 1000
	stable.Wrap = false

	if len(currentScanResult.Errors) != 0 {
		return "Error: Scan with --debug to view the details"
	}

	indexFormat := ""
	if len(currentScanResult.ScannedCves) < 10 {
		indexFormat = "[%1d]"
	} else if len(currentScanResult.ScannedCves) < 100 {
		indexFormat = "[%2d]"
	} else {
		indexFormat = "[%3d]"
	}

	for i, vinfo := range vinfos {
		summary := vinfo.Titles(
			config.Conf.Lang, currentScanResult.Family)[0].Value
		cvssScore := fmt.Sprintf("| %4.1f",
			vinfo.MaxCvssScore().Value.Score)

		var cols []string
		cols = []string{
			fmt.Sprintf(indexFormat, i+1),
			vinfo.CveID,
			cvssScore,
			fmt.Sprintf("| %3d |", vinfo.Confidence.Score),
			summary,
		}
		icols := make([]interface{}, len(cols))
		for j := range cols {
			icols[j] = cols[j]
		}
		stable.AddRow(icols...)
	}
	return fmt.Sprintf("%s", stable)
}

func setDetailLayout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	summaryView, err := g.View("summary")
	if err != nil {
		return err
	}
	_, cy := summaryView.Cursor()
	_, oy := summaryView.Origin()
	currentVinfo = cy + oy

	if v, err := g.SetView("detail", -1, int(float64(maxY)*0.2), int(float64(maxX)*0.5), maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		text, err := detailLines()
		if err != nil {
			return err
		}
		fmt.Fprint(v, text)
		v.Editable = false
		v.Wrap = true

		currentDetailLimitY = len(strings.Split(text, "\n")) - 1
	}
	return nil
}

func setChangelogLayout(g *gocui.Gui) error {
	maxX, maxY := g.Size()

	summaryView, err := g.View("summary")
	if err != nil {
		return err
	}
	_, cy := summaryView.Cursor()
	_, oy := summaryView.Origin()
	currentVinfo = cy + oy

	if v, err := g.SetView("changelog", int(float64(maxX)*0.5), int(float64(maxY)*0.2), maxX, maxY); err != nil {
		if err != gocui.ErrUnknownView {
			return err
		}
		if len(currentScanResult.Errors) != 0 || len(currentScanResult.ScannedCves) == 0 {
			return nil
		}

		lines := []string{}
		vinfo := vinfos[currentVinfo]
		for _, adv := range vinfo.DistroAdvisories {
			lines = append(lines, adv.Format())
		}

		for _, affected := range vinfo.AffectedPackages {
			pack := currentScanResult.Packages[affected.Name]
			for _, p := range currentScanResult.Packages {
				if pack.Name == p.Name {
					lines = append(lines, p.FormatChangelog(), "\n")
				}
			}
		}
		text := strings.Join(lines, "\n")
		fmt.Fprint(v, text)
		v.Editable = false
		v.Wrap = true

		currentChangelogLimitY = len(strings.Split(text, "\n")) - 1
	}
	return nil
}

type dataForTmpl struct {
	CveID            string
	Cvsses           string
	Summary          string
	Confidence       models.Confidence
	Cwes             []models.CveContentStr
	Links            []string
	References       []models.Reference
	Packages         []string
	CpeNames         []string
	PublishedDate    time.Time
	LastModifiedDate time.Time
}

func detailLines() (string, error) {
	r := currentScanResult
	if len(r.Errors) != 0 {
		return "", nil
	}

	if len(r.ScannedCves) == 0 {
		return "No vulnerable packages", nil
	}

	tmpl, err := template.New("detail").Parse(mdTemplate)
	if err != nil {
		return "", err
	}

	vinfo := vinfos[currentVinfo]

	packsVer := []string{}
	vinfo.AffectedPackages.Sort()
	for _, affected := range vinfo.AffectedPackages {
		// packages detected by OVAL may not be actually installed
		if pack, ok := r.Packages[affected.Name]; ok {
			packsVer = append(packsVer, pack.FormatVersionFromTo(affected.NotFixedYet))
		}
	}
	sort.Strings(vinfo.CpeNames)
	for _, name := range vinfo.CpeNames {
		packsVer = append(packsVer, name)
	}

	links := []string{vinfo.CveContents.SourceLinks(
		config.Conf.Lang, r.Family, vinfo.CveID)[0].Value,
		vinfo.Cvss2CalcURL(),
		vinfo.Cvss3CalcURL()}
	for _, url := range vinfo.VendorLinks(r.Family) {
		links = append(links, url)
	}

	refs := []models.Reference{}
	for _, rr := range vinfo.CveContents.References(r.Family) {
		for _, ref := range rr.Value {
			refs = append(refs, ref)
		}
	}

	summary := vinfo.Summaries(r.Lang, r.Family)[0]

	table := uitable.New()
	table.MaxColWidth = maxColWidth
	table.Wrap = true
	scores := append(vinfo.Cvss3Scores(), vinfo.Cvss2Scores()...)
	var cols []interface{}
	for _, score := range scores {
		cols = []interface{}{
			score.Value.Severity,
			score.Value.Format(),
			score.Type,
		}
		table.AddRow(cols...)
	}

	data := dataForTmpl{
		CveID:      vinfo.CveID,
		Cvsses:     fmt.Sprintf("%s\n", table),
		Summary:    fmt.Sprintf("%s (%s)", summary.Value, summary.Type),
		Confidence: vinfo.Confidence,
		Cwes:       vinfo.CveContents.CweIDs(r.Family),
		Links:      util.Distinct(links),
		Packages:   packsVer,
		References: refs,
	}

	buf := bytes.NewBuffer(nil) // create empty buffer
	if err := tmpl.Execute(buf, data); err != nil {
		return "", err
	}

	return string(buf.Bytes()), nil
}

const mdTemplate = `
{{.CveID}}
==============

CVSS Scores
--------------
{{.Cvsses }}

Summary
--------------
 {{.Summary }}


Links
--------------
{{range $link := .Links -}}
* {{$link}}
{{end}}

CWE
--------------
{{range .Cwes -}}
* {{.Value}} ({{.Type}})
{{end}}

Package/CPE
--------------
{{range $pack := .Packages -}}
* {{$pack}}
{{end -}}
{{range $name := .CpeNames -}}
* {{$name}}
{{end}}

Confidence
--------------
 {{.Confidence }}


References
--------------
{{range .References -}}
* [{{.Source}}]( {{.Link}} )
{{end}}

`
