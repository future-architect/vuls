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

	"github.com/future-architect/vuls/models"
)

// TextWriter write to stdout
type TextWriter struct{}

func (w TextWriter) Write(scanResults []models.ScanResult) error {
	for _, s := range scanResults {
		text, err := toPlainText(s)
		if err != nil {
			return err
		}
		fmt.Println(text)
	}
	return nil
}
