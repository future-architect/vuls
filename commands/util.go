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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
)

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
// 2016-11-16T10:43:28Z
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$`)

// JSONDirs is array of json files path.
type jsonDirs []string

// sort as recent directories are at the head
func (d jsonDirs) Len() int {
	return len(d)
}
func (d jsonDirs) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}
func (d jsonDirs) Less(i, j int) bool {
	return d[j] < d[i]
}

// getValidJSONDirs return valid json directory as array
// Returned array is sorted so that recent directories are at the head
func lsValidJSONDirs() (dirs jsonDirs, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(c.Conf.ResultsDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", c.Conf.ResultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && jsonDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(c.Conf.ResultsDir, d.Name())
			dirs = append(dirs, jsonDir)
		}
	}
	sort.Sort(dirs)
	return
}

// jsonDir returns
// If there is an arg, check if it is a valid format and return the corresponding path under results.
// If arg passed via PIPE (such as history subcommand), return that path.
// Otherwise, returns the path of the latest directory
func jsonDir(args []string) (string, error) {
	var err error
	var dirs jsonDirs

	if 0 < len(args) {
		if dirs, err = lsValidJSONDirs(); err != nil {
			return "", err
		}

		path := filepath.Join(c.Conf.ResultsDir, args[0])
		for _, d := range dirs {
			ss := strings.Split(d, string(os.PathSeparator))
			timedir := ss[len(ss)-1]
			if timedir == args[0] {
				return path, nil
			}
		}

		return "", fmt.Errorf("Invalid path: %s", path)
	}

	// PIPE
	if c.Conf.Pipe {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("Failed to read stdin: %s", err)
		}
		fields := strings.Fields(string(bytes))
		if 0 < len(fields) {
			return filepath.Join(c.Conf.ResultsDir, fields[0]), nil
		}
		return "", fmt.Errorf("Stdin is invalid: %s", string(bytes))
	}

	// returns latest dir when no args or no PIPE
	if dirs, err = lsValidJSONDirs(); err != nil {
		return "", err
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("No results under %s",
			c.Conf.ResultsDir)
	}
	return dirs[0], nil
}

// loadOneScanHistory read JSON data
func loadOneScanHistory(jsonDir string) (scanHistory models.ScanHistory, err error) {
	var results []models.ScanResult
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", jsonDir, err)
		return
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" {
			continue
		}
		var r models.ScanResult
		var data []byte
		path := filepath.Join(jsonDir, f.Name())
		if data, err = ioutil.ReadFile(path); err != nil {
			err = fmt.Errorf("Failed to read %s: %s", path, err)
			return
		}
		if json.Unmarshal(data, &r) != nil {
			err = fmt.Errorf("Failed to parse %s: %s", path, err)
			return
		}
		results = append(results, r)
	}
	if len(results) == 0 {
		err = fmt.Errorf("There is no json file under %s", jsonDir)
		return
	}

	scanHistory = models.ScanHistory{
		ScanResults: results,
	}
	return
}

func fillCveInfoFromCveDB(r models.ScanResult) (filled models.ScanResult, err error) {
	sInfo := c.Conf.Servers[r.ServerName]
	vs, err := scanVulnByCpeNames(sInfo.CpeNames, r.ScannedCves)
	if err != nil {
		return
	}
	r.ScannedCves = vs
	filled, err = r.FillCveDetail()
	if err != nil {
		return
	}
	return
}

func overwriteJSONFile(dir string, r models.ScanResult) error {
	before := c.Conf.FormatJSON
	c.Conf.FormatJSON = true
	w := report.LocalFileWriter{CurrentDir: dir}
	if err := w.Write(r); err != nil {
		return fmt.Errorf("Failed to write summary report: %s", err)
	}
	c.Conf.FormatJSON = before
	return nil
}

func scanVulnByCpeNames(cpeNames []string, scannedVulns []models.VulnInfo) ([]models.VulnInfo,
	error) {
	// To remove duplicate
	set := map[string]models.VulnInfo{}
	for _, v := range scannedVulns {
		set[v.CveID] = v
	}

	for _, name := range cpeNames {
		details, err := cveapi.CveClient.FetchCveDetailsByCpeName(name)
		if err != nil {
			return nil, err
		}
		for _, detail := range details {
			if val, ok := set[detail.CveID]; ok {
				names := val.CpeNames
				names = util.AppendIfMissing(names, name)
				val.CpeNames = names
				val.Confidence = models.CpeNameMatch
				set[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:      detail.CveID,
					CpeNames:   []string{name},
					Confidence: models.CpeNameMatch,
				}
				v.NilSliceToEmpty()
				set[detail.CveID] = v
			}
		}
	}

	vinfos := []models.VulnInfo{}
	for key := range set {
		vinfos = append(vinfos, set[key])
	}
	return vinfos, nil
}

func needToRefreshCve(r models.ScanResult) bool {
	return r.Lang != c.Conf.Lang || len(r.KnownCves) == 0 &&
		len(r.UnknownCves) == 0 &&
		len(r.IgnoredCves) == 0
}
