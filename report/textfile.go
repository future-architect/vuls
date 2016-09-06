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
	"io/ioutil"
	"path/filepath"
	"strings"
	"time"

	"github.com/future-architect/vuls/models"
)

// TextFileWriter writes results to file.
type TextFileWriter struct {
	ScannedAt time.Time
}

func (w TextFileWriter) Write(scanResults []models.ScanResult) (err error) {
	path, err := ensureResultDir(w.ScannedAt)
	all := []string{}
	for _, r := range scanResults {
		textFilePath := ""
		if len(r.Container.ContainerID) == 0 {
			textFilePath = filepath.Join(path, fmt.Sprintf("%s.txt", r.ServerName))
		} else {
			textFilePath = filepath.Join(path,
				fmt.Sprintf("%s_%s.txt", r.ServerName, r.Container.Name))
		}
		text, err := toPlainText(r)
		if err != nil {
			return err
		}
		all = append(all, text)
		b := []byte(text)
		if err := ioutil.WriteFile(textFilePath, b, 0644); err != nil {
			return fmt.Errorf("Failed to write text files. path: %s, err: %s", textFilePath, err)
		}
	}

	text := strings.Join(all, "\n\n")
	b := []byte(text)
	allPath := filepath.Join(path, "all.txt")
	if err := ioutil.WriteFile(allPath, b, 0644); err != nil {
		return fmt.Errorf("Failed to write text files. path: %s, err: %s", allPath, err)
	}
	return nil
}
