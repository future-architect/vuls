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
	"fmt"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// StdoutWriter write to stdout
type StdoutWriter struct{}

// WriteScanSummary prints Scan summary at the end of scan
func (w StdoutWriter) WriteScanSummary(rs ...models.ScanResult) {
	fmt.Printf("\n\n")
	fmt.Println("One Line Summary")
	fmt.Println("================")
	fmt.Printf("%s\n", formatScanSummary(rs...))
}

func (w StdoutWriter) Write(rs ...models.ScanResult) error {
	if c.Conf.FormatOneLineText {
		fmt.Print("\n\n")
		fmt.Println("One Line Summary")
		fmt.Println("================")
		fmt.Println(formatOneLineSummary(rs...))
		fmt.Print("\n")
	}

	if c.Conf.FormatShortText {
		for _, r := range rs {
			fmt.Println(formatShortPlainText(r))
		}
	}

	if c.Conf.FormatFullText {
		for _, r := range rs {
			fmt.Println(formatFullPlainText(r))
		}
	}
	return nil
}
