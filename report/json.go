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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/future-architect/vuls/models"
)

// JSONWriter writes results to file.
type JSONWriter struct{}

func (w JSONWriter) Write(scanResults []models.ScanResult) (err error) {

	path, err := ensureResultDir()

	var jsonBytes []byte
	if jsonBytes, err = json.MarshalIndent(scanResults, "", "  "); err != nil {
		return fmt.Errorf("Failed to Marshal to JSON: %s", err)
	}
	all := filepath.Join(path, "all.json")
	if err := ioutil.WriteFile(all, jsonBytes, 0644); err != nil {
		return fmt.Errorf("Failed to write JSON. path: %s, err: %s", all, err)
	}

	for _, r := range scanResults {
		jsonPath := ""
		if r.Container.ContainerID == "" {
			jsonPath = filepath.Join(path, fmt.Sprintf("%s.json", r.ServerName))
		} else {
			jsonPath = filepath.Join(path,
				fmt.Sprintf("%s_%s.json", r.ServerName, r.Container.Name))

		}
		if jsonBytes, err = json.MarshalIndent(r, "", "  "); err != nil {
			return fmt.Errorf("Failed to Marshal to JSON: %s", err)
		}
		if err := ioutil.WriteFile(jsonPath, jsonBytes, 0644); err != nil {
			return fmt.Errorf("Failed to write JSON. path: %s, err: %s", all, err)
		}
	}
	return nil
}
