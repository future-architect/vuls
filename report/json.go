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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// JSONDirs array of json files path.
type JSONDirs []string

func (d JSONDirs) Len() int {
	return len(d)
}
func (d JSONDirs) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d JSONDirs) Less(i, j int) bool {
	return d[j] < d[i]
}

// JSONWriter writes results to file.
type JSONWriter struct {
	ScannedAt time.Time
}

func (w JSONWriter) Write(scanResults []models.ScanResult) (err error) {
	var path string
	if path, err = ensureResultDir(w.ScannedAt); err != nil {
		return fmt.Errorf("Failed to make direcotory/symlink : %s", err)
	}

	for _, scanResult := range scanResults {
		scanResult.ScannedAt = w.ScannedAt
	}

	var jsonBytes []byte
	for _, r := range scanResults {
		jsonPath := ""
		if len(r.Container.ContainerID) == 0 {
			jsonPath = filepath.Join(path, fmt.Sprintf("%s.json", r.ServerName))
		} else {
			jsonPath = filepath.Join(path,
				fmt.Sprintf("%s_%s.json", r.ServerName, r.Container.Name))
		}

		if jsonBytes, err = json.Marshal(r); err != nil {
			return fmt.Errorf("Failed to Marshal to JSON: %s", err)
		}
		if err := ioutil.WriteFile(jsonPath, jsonBytes, 0600); err != nil {
			return fmt.Errorf("Failed to write JSON. path: %s, err: %s", jsonPath, err)
		}
	}
	return nil
}

// JSONDirPattern is file name pattern of JSON directory
var JSONDirPattern = regexp.MustCompile(`^\d{8}_\d{4}$`)

// GetValidJSONDirs return valid json directory as array
func GetValidJSONDirs() (jsonDirs JSONDirs, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(c.Conf.ResultsDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", c.Conf.ResultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && JSONDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(c.Conf.ResultsDir, d.Name())
			jsonDirs = append(jsonDirs, jsonDir)
		}
	}
	sort.Sort(jsonDirs)
	return
}

// LoadOneScanHistory read JSON data
func LoadOneScanHistory(jsonDir string) (scanHistory models.ScanHistory, err error) {
	var scanResults []models.ScanResult
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", jsonDir, err)
		return
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		var scanResult models.ScanResult
		var data []byte
		jsonPath := filepath.Join(jsonDir, file.Name())
		if data, err = ioutil.ReadFile(jsonPath); err != nil {
			err = fmt.Errorf("Failed to read %s: %s", jsonPath, err)
			return
		}
		if json.Unmarshal(data, &scanResult) != nil {
			err = fmt.Errorf("Failed to parse %s: %s", jsonPath, err)
			return
		}
		scanResults = append(scanResults, scanResult)
	}
	if len(scanResults) == 0 {
		err = fmt.Errorf("There is no json file under %s", jsonDir)
		return
	}

	var scannedAt time.Time
	if scanResults[0].ScannedAt.IsZero() {
		splitPath := strings.Split(jsonDir, string(os.PathSeparator))
		timeStr := splitPath[len(splitPath)-1]
		timeformat := "20060102_1504"
		if scannedAt, err = time.Parse(timeformat, timeStr); err != nil {
			err = fmt.Errorf("Failed to parse %s: %s", timeStr, err)
			return
		}
	} else {
		scannedAt = scanResults[0].ScannedAt
	}

	scanHistory = models.ScanHistory{
		ScanResults: scanResults,
		ScannedAt:   scannedAt,
	}
	return
}
