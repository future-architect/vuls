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
	"github.com/future-architect/vuls/oval"
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

func fillCveInfoFromCveDB(r models.ScanResult) (*models.ScanResult, error) {
	var err error
	var vs []models.VulnInfo

	sInfo := c.Conf.Servers[r.ServerName]
	vs, err = scanVulnByCpeNames(sInfo.CpeNames, r.ScannedCves)
	if err != nil {
		return nil, err
	}
	r.ScannedCves = vs
	return r.FillCveDetail()
}

func fillCveInfoFromOvalDB(r *models.ScanResult) (*models.ScanResult, error) {
	var ovalClient oval.Client
	switch r.Family {
	case "ubuntu", "debian":
		ovalClient = oval.NewDebian()
	case "rhel", "centos":
		ovalClient = oval.NewRedhat()
	case "amazon", "oraclelinux", "Raspbian", "FreeBSD":
		//TODO implement OracleLinux
		return r, nil
	default:
		return nil, fmt.Errorf("Oval %s is not implemented yet", r.Family)
	}
	result, err := ovalClient.FillCveInfoFromOvalDB(r)
	if err != nil {
		return nil, err
	}
	return result, nil
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

func diff(current, previous models.ScanResults) (diff models.ScanResults, err error) {
	for _, currentResult := range current {
		found := false
		var previousResult models.ScanResult
		for _, previousResult = range previous {
			if currentResult.ServerName == previousResult.ServerName {
				found = true
				break
			}
		}

		if found {
			currentResult.ScannedCves = getNewCves(previousResult, currentResult)

			//TODO
			//  currentResult.KnownCves = []models.CveInfo{}
			//  currentResult.UnknownCves = []models.CveInfo{}

			currentResult.Packages = models.PackageInfoList{}
			for _, s := range currentResult.ScannedCves {
				currentResult.Packages = append(currentResult.Packages, s.Packages...)
			}
			currentResult.Packages = currentResult.Packages.UniqByName()
		}

		diff = append(diff, currentResult)
	}
	return diff, err
}

func getNewCves(previous, current models.ScanResult) (newVulninfos []models.VulnInfo) {
	previousCveIDsSet := map[string]bool{}
	for _, previousVulnInfo := range previous.ScannedCves {
		previousCveIDsSet[previousVulnInfo.CveID] = true
	}

	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(current, previous, v.CveID) {
				newVulninfos = append(newVulninfos, v)
			}
		} else {
			newVulninfos = append(newVulninfos, v)
		}
	}
	return
}

func isCveInfoUpdated(current, previous models.ScanResult, CveID string) bool {
	type lastModified struct {
		Nvd time.Time
		Jvn time.Time
	}

	//TODO
	previousModifies := lastModified{}
	for _, c := range previous.ScannedCves {
		if CveID == c.CveID {
			//TODO
			if nvd, found := c.CveContents.Get(models.NVD); found {
				previousModifies.Nvd = nvd.LastModified
			}
			if jvn, found := c.CveContents.Get(models.JVN); found {
				previousModifies.Jvn = jvn.LastModified
			}
		}
	}

	currentModifies := lastModified{}
	for _, c := range current.ScannedCves {
		if CveID == c.CveID {
			//TODO
			if nvd, found := c.CveContents.Get(models.NVD); found {
				previousModifies.Nvd = nvd.LastModified
			}
			if jvn, found := c.CveContents.Get(models.JVN); found {
				previousModifies.Jvn = jvn.LastModified
			}
		}
	}
	return !currentModifies.Nvd.Equal(previousModifies.Nvd) ||
		!currentModifies.Jvn.Equal(previousModifies.Jvn)
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

func scanVulnByCpeNames(cpeNames []string, scannedVulns []models.VulnInfo) ([]models.VulnInfo, error) {
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
