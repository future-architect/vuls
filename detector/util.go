//go:build !scanner

package detector

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/gost"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"golang.org/x/xerrors"
)

func reuseScannedCves(r *models.ScanResult) bool {
	switch r.Family {
	case constant.FreeBSD, constant.Raspbian:
		return true
	}
	return r.ScannedBy == "trivy"
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
			}
			logging.Log.Infof("Previous json is different family.Release: %s, pre: %s.%s cur: %s.%s",
				path, r.Family, r.Release, result.Family, result.Release)
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
				maps.Copy(cves, minus)
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

	newer := models.VulnInfos{}
	updated := models.VulnInfos{}
	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(v.CveID, previous, current) {
				v.DiffStatus = models.DiffPlus
				updated[v.CveID] = v
				logging.Log.Debugf("updated: %s", v.CveID)

				// TODO commented out because  a bug of diff logic when multiple oval defs found for a certain CVE-ID and same updated_at
				// if these OVAL defs have different affected packages, this logic detects as updated.
				// This logic will be uncommented after integration with gost https://github.com/vulsio/gost
				// } else if isCveFixed(v, previous) {
				// updated[v.CveID] = v
				// logging.Log.Debugf("fixed: %s", v.CveID)

			} else {
				logging.Log.Debugf("same: %s", v.CveID)
			}
		} else {
			logging.Log.Debugf("newer: %s", v.CveID)
			v.DiffStatus = models.DiffPlus
			newer[v.CveID] = v
		}
	}

	if len(updated) == 0 && len(newer) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	maps.Copy(updated, newer)
	return updated
}

func getMinusDiffCves(previous, current models.ScanResult) models.VulnInfos {
	currentCveIDsSet := map[string]bool{}
	for _, currentVulnInfo := range current.ScannedCves {
		currentCveIDsSet[currentVulnInfo.CveID] = true
	}

	removed := models.VulnInfos{}
	for _, v := range previous.ScannedCves {
		if !currentCveIDsSet[v.CveID] {
			v.DiffStatus = models.DiffMinus
			removed[v.CveID] = v
			logging.Log.Debugf("clear: %s", v.CveID)
		}
	}
	if len(removed) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	return removed
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := append([]models.CveContentType{models.Mitre, models.Nvd, models.Vulncheck, models.Jvn, models.Euvd}, models.GetCveContentTypes(current.Family)...)

	prevLastModified := map[models.CveContentType][]time.Time{}
	preVinfo, ok := previous.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if conts, ok := preVinfo.CveContents[cType]; ok {
			for _, cont := range conts {
				prevLastModified[cType] = append(prevLastModified[cType], cont.LastModified)
			}
		}
	}

	curLastModified := map[models.CveContentType][]time.Time{}
	curVinfo, ok := current.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if conts, ok := curVinfo.CveContents[cType]; ok {
			for _, cont := range conts {
				curLastModified[cType] = append(curLastModified[cType], cont.LastModified)
			}
		}
	}

	for _, t := range cTypes {
		if !reflect.DeepEqual(curLastModified[t], prevLastModified[t]) {
			logging.Log.Debugf("%s LastModified not equal: \n%s\n%s",
				cveID, curLastModified[t], prevLastModified[t])
			return true
		}
	}
	return false
}

// ListValidJSONDirs returns valid json directory as array
// Returned array is sorted so that recent directories are at the head
func ListValidJSONDirs(resultsDir string) (dirs []string, err error) {
	dirInfo, err := os.ReadDir(resultsDir)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", config.Conf.ResultsDir, err)
	}
	for _, d := range dirInfo {
		if !d.IsDir() {
			continue
		}

		for _, layout := range []string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05-07:00", "2006-01-02T15-04-05-0700"} {
			if _, err := time.Parse(layout, d.Name()); err == nil {
				dirs = append(dirs, filepath.Join(resultsDir, d.Name()))
				break
			}
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
	if data, err = os.ReadFile(jsonFile); err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", jsonFile, err)
	}
	result := &models.ScanResult{}
	if err := json.Unmarshal(data, result); err != nil {
		return nil, xerrors.Errorf("Failed to parse %s: %w", jsonFile, err)
	}

	for k, v := range result.ScannedCves {
		if v.CveContents == nil {
			v.CveContents = models.NewCveContents()
			result.ScannedCves[k] = v
		}
	}
	return result, nil
}

// ValidateDBs checks if the databases are accessible and can be closed properly
func ValidateDBs(cveConf config.GoCveDictConf, ovalConf config.GovalDictConf, gostConf config.GostConf, exploitConf config.ExploitConf, metasploitConf config.MetasploitConf, kevulnConf config.KEVulnConf, ctiConf config.CtiConf, logOpts logging.LogOpts) error {
	cvec, err := newGoCveDictClient(&cveConf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new CVE client. err: %w", err)
	}
	if err := cvec.closeDB(); err != nil {
		return xerrors.Errorf("Failed to close CVE DB. err: %w", err)
	}

	ovalc, err := oval.NewOVALClient(constant.ServerTypePseudo, ovalConf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new OVAL client. err: %w", err)
	}
	if err := ovalc.CloseDB(); err != nil {
		return xerrors.Errorf("Failed to close OVAL DB. err: %w", err)
	}

	gostc, err := gost.NewGostClient(gostConf, constant.ServerTypePseudo, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new gost client. err: %w", err)
	}
	if err := gostc.CloseDB(); err != nil {
		return xerrors.Errorf("Failed to close gost DB. err: %w", err)
	}

	exploitc, err := newGoExploitDBClient(&exploitConf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new exploit client. err: %w", err)
	}
	if err := exploitc.closeDB(); err != nil {
		return xerrors.Errorf("Failed to close exploit DB. err: %w", err)
	}

	metasploitc, err := newGoMetasploitDBClient(&metasploitConf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new metasploit client. err: %w", err)
	}
	if err := metasploitc.closeDB(); err != nil {
		return xerrors.Errorf("Failed to close metasploit DB. err: %w", err)
	}

	kevulnc, err := newGoKEVulnDBClient(&kevulnConf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new KEVuln client. err: %w", err)
	}
	if err := kevulnc.closeDB(); err != nil {
		return xerrors.Errorf("Failed to close KEVuln DB. err: %w", err)
	}

	ctic, err := newGoCTIDBClient(&ctiConf, logOpts)
	if err != nil {
		return xerrors.Errorf("Failed to new CTI client. err: %w", err)
	}
	if err := ctic.closeDB(); err != nil {
		return xerrors.Errorf("Failed to close CTI DB. err: %w", err)
	}

	return nil
}
