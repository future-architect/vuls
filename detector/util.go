// +build !scanner

package detector

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"golang.org/x/xerrors"
)

func reuseScannedCves(r *models.ScanResult) bool {
	switch r.Family {
	case constant.FreeBSD, constant.Raspbian:
		return true
	}
	if isTrivyResult(r) {
		return true
	}
	return false
}

func isTrivyResult(r *models.ScanResult) bool {
	_, ok := r.Optional["trivy-target"]
	return ok
}

func needToRefreshCve(r models.ScanResult) bool {
	for _, cve := range r.ScannedCves {
		if 0 < len(cve.CveContents) {
			return false
		}
	}
	return true
}

func loadPrevious(currs models.ScanResults, resultsDir string) (prevs models.ScanResults, err error) {
	dirs, err := ListValidJSONDirs(resultsDir)
	if err != nil {
		return
	}

	for _, result := range currs {
		filename := result.ServerName + ".json"
		if result.Container.Name != "" {
			filename = fmt.Sprintf("%s@%s.json", result.Container.Name, result.ServerName)
		}
		for _, dir := range dirs[1:] {
			path := filepath.Join(dir, filename)
			r, err := loadOneServerScanResult(path)
			if err != nil {
				logging.Log.Debugf("%+v", err)
				continue
			}
			if r.Family == result.Family && r.Release == result.Release {
				prevs = append(prevs, *r)
				logging.Log.Infof("Previous json found: %s", path)
				break
			} else {
				logging.Log.Infof("Previous json is different family.Release: %s, pre: %s.%s cur: %s.%s",
					path, r.Family, r.Release, result.Family, result.Release)
			}
		}
	}
	return prevs, nil
}

func diff(curResults, preResults models.ScanResults, isPlus, isMinus bool) (diffed models.ScanResults) {
	for _, current := range curResults {
		found := false
		var previous models.ScanResult
		for _, r := range preResults {
			if current.ServerName == r.ServerName && current.Container.Name == r.Container.Name {
				found = true
				previous = r
				break
			}
		}

		if !found {
			diffed = append(diffed, current)
			continue
		}

		cves := models.VulnInfos{}
		if isPlus {
			cves = getPlusDiffCves(previous, current)
		}
		if isMinus {
			minus := getMinusDiffCves(previous, current)
			if len(cves) == 0 {
				cves = minus
			} else {
				for k, v := range minus {
					cves[k] = v
				}
			}
		}

		packages := models.Packages{}
		for _, s := range cves {
			for _, affected := range s.AffectedPackages {
				var p models.Package
				if s.DiffStatus == models.DiffPlus {
					p = current.Packages[affected.Name]
				} else {
					p = previous.Packages[affected.Name]
				}
				packages[affected.Name] = p
			}
		}
		current.ScannedCves = cves
		current.Packages = packages
		diffed = append(diffed, current)
	}
	return
}

func getPlusDiffCves(previous, current models.ScanResult) models.VulnInfos {
	previousCveIDsSet := map[string]bool{}
	for _, previousVulnInfo := range previous.ScannedCves {
		previousCveIDsSet[previousVulnInfo.CveID] = true
	}

	new := models.VulnInfos{}
	updated := models.VulnInfos{}
	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(v.CveID, previous, current) {
				v.DiffStatus = models.DiffPlus
				updated[v.CveID] = v
				logging.Log.Debugf("updated: %s", v.CveID)

				// TODO commented out because  a bug of diff logic when multiple oval defs found for a certain CVE-ID and same updated_at
				// if these OVAL defs have different affected packages, this logic detects as updated.
				// This logic will be uncomented after integration with gost https://github.com/knqyf263/gost
				// } else if isCveFixed(v, previous) {
				// updated[v.CveID] = v
				// logging.Log.Debugf("fixed: %s", v.CveID)

			} else {
				logging.Log.Debugf("same: %s", v.CveID)
			}
		} else {
			logging.Log.Debugf("new: %s", v.CveID)
			v.DiffStatus = models.DiffPlus
			new[v.CveID] = v
		}
	}

	if len(updated) == 0 && len(new) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	for cveID, vuln := range new {
		updated[cveID] = vuln
	}
	return updated
}

func getMinusDiffCves(previous, current models.ScanResult) models.VulnInfos {
	currentCveIDsSet := map[string]bool{}
	for _, currentVulnInfo := range current.ScannedCves {
		currentCveIDsSet[currentVulnInfo.CveID] = true
	}

	clear := models.VulnInfos{}
	for _, v := range previous.ScannedCves {
		if !currentCveIDsSet[v.CveID] {
			v.DiffStatus = models.DiffMinus
			clear[v.CveID] = v
			logging.Log.Debugf("clear: %s", v.CveID)
		}
	}
	if len(clear) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	return clear
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := []models.CveContentType{
		models.Nvd,
		models.Jvn,
		models.NewCveContentType(current.Family),
	}

	prevLastModified := map[models.CveContentType]time.Time{}
	preVinfo, ok := previous.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if content, ok := preVinfo.CveContents[cType]; ok {
			prevLastModified[cType] = content.LastModified
		}
	}

	curLastModified := map[models.CveContentType]time.Time{}
	curVinfo, ok := current.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if content, ok := curVinfo.CveContents[cType]; ok {
			curLastModified[cType] = content.LastModified
		}
	}

	for _, t := range cTypes {
		if !curLastModified[t].Equal(prevLastModified[t]) {
			logging.Log.Debugf("%s LastModified not equal: \n%s\n%s",
				cveID, curLastModified[t], prevLastModified[t])
			return true
		}
	}
	return false
}

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
// 2016-11-16T10:43:28Z
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$`)

// ListValidJSONDirs returns valid json directory as array
// Returned array is sorted so that recent directories are at the head
func ListValidJSONDirs(resultsDir string) (dirs []string, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(resultsDir); err != nil {
		err = xerrors.Errorf("Failed to read %s: %w",
			config.Conf.ResultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && jsonDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(resultsDir, d.Name())
			dirs = append(dirs, jsonDir)
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[j] < dirs[i]
	})
	return
}

// loadOneServerScanResult read JSON data of one server
func loadOneServerScanResult(jsonFile string) (*models.ScanResult, error) {
	var (
		data []byte
		err  error
	)
	if data, err = ioutil.ReadFile(jsonFile); err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", jsonFile, err)
	}
	result := &models.ScanResult{}
	if err := json.Unmarshal(data, result); err != nil {
		return nil, xerrors.Errorf("Failed to parse %s: %w", jsonFile, err)
	}
	return result, nil
}
