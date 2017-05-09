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
	"time"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cveapi"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/report"
	"github.com/future-architect/vuls/util"
	"github.com/howeyc/gopass"
)

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
// 2016-11-16T10:43:28Z
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$`)

// JSONDirs is array of json files path.
type jsonDirs []string

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
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[j] < dirs[i]
	})
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

// loadOneServerScanResult read JSON data of one server
func loadOneServerScanResult(jsonFile string) (result models.ScanResult, err error) {
	var data []byte
	if data, err = ioutil.ReadFile(jsonFile); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", jsonFile, err)
		return
	}
	if json.Unmarshal(data, &result) != nil {
		err = fmt.Errorf("Failed to parse %s: %s", jsonFile, err)
	}
	return
}

// loadScanResults read JSON data
func loadScanResults(jsonDir string) (results models.ScanResults, err error) {
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		return nil, fmt.Errorf("Failed to read %s: %s", jsonDir, err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" || strings.HasSuffix(f.Name(), "_diff.json") {
			continue
		}

		var r models.ScanResult
		path := filepath.Join(jsonDir, f.Name())
		if r, err = loadOneServerScanResult(path); err != nil {
			return nil, err
		}

		results = append(results, r)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("There is no json file under %s", jsonDir)
	}
	return
}

func loadPrevious(current models.ScanResults) (previous models.ScanResults, err error) {
	var dirs jsonDirs
	if dirs, err = lsValidJSONDirs(); err != nil {
		return
	}

	for _, result := range current {
		for _, dir := range dirs[1:] {
			var r models.ScanResult
			path := filepath.Join(dir, result.ServerName+".json")
			if r, err = loadOneServerScanResult(path); err != nil {
				continue
			}
			if r.Family == result.Family && r.Release == result.Release {
				previous = append(previous, r)
				util.Log.Infof("Privious json found: %s", path)
				break
			}
		}
	}
	return previous, nil
}

func diff(curResults, preResults models.ScanResults) (diffed models.ScanResults, err error) {
	for _, current := range curResults {
		found := false
		var previous models.ScanResult
		for _, r := range preResults {
			if current.ServerName == r.ServerName {
				found = true
				previous = r
				break
			}
		}

		if found {
			current.ScannedCves = getDiffCves(previous, current)
			packages := models.Packages{}
			for _, s := range current.ScannedCves {
				for _, name := range s.PackageNames {
					p := current.Packages[name]
					packages[name] = p
				}
			}
			current.Packages = packages
		}

		diffed = append(diffed, current)
	}
	return diffed, err
}

func getDiffCves(previous, current models.ScanResult) models.VulnInfos {
	previousCveIDsSet := map[string]bool{}
	for _, previousVulnInfo := range previous.ScannedCves {
		previousCveIDsSet[previousVulnInfo.CveID] = true
	}

	new := models.VulnInfos{}
	updated := models.VulnInfos{}
	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(v.CveID, previous, current) {
				updated[v.CveID] = v
			}
		} else {
			new[v.CveID] = v
		}
	}

	for cveID, vuln := range new {
		updated[cveID] = vuln
	}
	return updated
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := []models.CveContentType{
		models.NVD,
		models.JVN,
		models.NewCveContentType(current.Family),
	}

	prevLastModified := map[models.CveContentType]time.Time{}
	for _, c := range previous.ScannedCves {
		if cveID == c.CveID {
			for _, cType := range cTypes {
				content, _ := c.CveContents.Get(cType)
				prevLastModified[cType] = content.LastModified
			}
			break
		}
	}

	curLastModified := map[models.CveContentType]time.Time{}
	for _, c := range current.ScannedCves {
		if cveID == c.CveID {
			for _, cType := range cTypes {
				content, _ := c.CveContents.Get(cType)
				curLastModified[cType] = content.LastModified
			}
			break
		}
	}
	for _, cType := range cTypes {
		if equal := prevLastModified[cType].Equal(curLastModified[cType]); !equal {
			return true
		}
	}
	return false
}

func overwriteJSONFile(dir string, r models.ScanResult) error {
	before := c.Conf.FormatJSON
	beforeDiff := c.Conf.Diff
	c.Conf.FormatJSON = true
	c.Conf.Diff = false
	w := report.LocalFileWriter{CurrentDir: dir}
	if err := w.Write(r); err != nil {
		return fmt.Errorf("Failed to write summary report: %s", err)
	}
	c.Conf.FormatJSON = before
	c.Conf.Diff = beforeDiff
	return nil
}

func fillVulnByCpeNames(cpeNames []string, scannedVulns models.VulnInfos) error {
	for _, name := range cpeNames {
		details, err := cveapi.CveClient.FetchCveDetailsByCpeName(name)
		if err != nil {
			return err
		}
		for _, detail := range details {
			if val, ok := scannedVulns[detail.CveID]; ok {
				names := val.CpeNames
				names = util.AppendIfMissing(names, name)
				val.CpeNames = names
				val.Confidence = models.CpeNameMatch
				scannedVulns[detail.CveID] = val
			} else {
				v := models.VulnInfo{
					CveID:      detail.CveID,
					CpeNames:   []string{name},
					Confidence: models.CpeNameMatch,
				}
				//TODO
				//  v.NilToEmpty()
				scannedVulns[detail.CveID] = v
			}
		}
	}
	return nil
}

func needToRefreshCve(r models.ScanResult) bool {
	if r.Lang != c.Conf.Lang {
		return true
	}

	for _, cve := range r.ScannedCves {
		if 0 < len(cve.CveContents) {
			return false
		}
	}
	return true
}

func getPasswd(prompt string) (string, error) {
	for {
		fmt.Print(prompt)
		pass, err := gopass.GetPasswdMasked()
		if err != nil {
			return "", fmt.Errorf("Failed to read password")
		}
		if 0 < len(pass) {
			return string(pass[:]), nil
		}
	}

}
