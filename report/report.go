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
	"strings"
	"time"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/oval"
	"github.com/future-architect/vuls/util"
)

const (
	vulsOpenTag  = "<vulsreport>"
	vulsCloseTag = "</vulsreport>"
)

// FillCveInfos fills CVE Detailed Information
func FillCveInfos(rs []models.ScanResult, dir string) ([]models.ScanResult, error) {
	var filled []models.ScanResult
	reportedAt := time.Now()
	for _, r := range rs {
		if c.Conf.RefreshCve || needToRefreshCve(r) {
			if err := FillCveInfo(&r); err != nil {
				return nil, err
			}
			r.Lang = c.Conf.Lang
			r.ReportedAt = reportedAt
			r.Config.Report = c.Conf
			r.Config.Report.Servers = map[string]c.ServerInfo{
				r.ServerName: c.Conf.Servers[r.ServerName],
			}
			if err := overwriteJSONFile(dir, r); err != nil {
				return nil, fmt.Errorf("Failed to write JSON: %s", err)
			}
			filled = append(filled, r)
		} else {
			util.Log.Debugf("No need to refresh")
			filled = append(filled, r)
		}
	}

	if c.Conf.Diff {
		previous, err := loadPrevious(filled)
		if err != nil {
			return nil, err
		}

		diff, err := diff(filled, previous)
		if err != nil {
			return nil, err
		}
		filled = []models.ScanResult{}
		for _, r := range diff {
			if err := fillCveDetail(&r); err != nil {
				return nil, err
			}
			filled = append(filled, r)
		}
	}

	filtered := []models.ScanResult{}
	for _, r := range filled {
		r = r.FilterByCvssOver(c.Conf.CvssScoreOver)
		r = r.FilterIgnoreCves(c.Conf.Servers[r.ServerName].IgnoreCves)
		filtered = append(filtered, r)
	}
	return filtered, nil
}

// FillCveInfo fill scanResult with cve info.
func FillCveInfo(r *models.ScanResult) error {
	util.Log.Debugf("need to refresh")

	util.Log.Infof("Fill CVE detailed information with OVAL")
	if err := FillWithOval(r); err != nil {
		return fmt.Errorf("Failed to fill OVAL information: %s", err)
	}

	util.Log.Infof("Fill CVE detailed information with CVE-DB")
	if err := fillWithCveDB(r); err != nil {
		return fmt.Errorf("Failed to fill CVE information: %s", err)
	}

	for cveID := range r.ScannedCves {
		vinfo := r.ScannedCves[cveID]
		r.ScannedCves[cveID] = *vinfo.NilToEmpty()
	}
	return nil
}

// fillCveDetail fetches NVD, JVN from CVE Database, and then set to fields.
func fillCveDetail(r *models.ScanResult) error {
	var cveIDs []string
	for _, v := range r.ScannedCves {
		cveIDs = append(cveIDs, v.CveID)
	}

	ds, err := CveClient.FetchCveDetails(cveIDs)
	if err != nil {
		return err
	}
	for _, d := range ds {
		nvd := models.ConvertNvdToModel(d.CveID, d.Nvd)
		jvn := models.ConvertJvnToModel(d.CveID, d.Jvn)
		for cveID, vinfo := range r.ScannedCves {
			if vinfo.CveID == d.CveID {
				if vinfo.CveContents == nil {
					vinfo.CveContents = models.CveContents{}
				}
				for _, con := range []models.CveContent{*nvd, *jvn} {
					if !con.Empty() {
						vinfo.CveContents[con.Type] = con
					}
				}
				r.ScannedCves[cveID] = vinfo
				break
			}
		}
	}
	return nil
}

func fillWithCveDB(r *models.ScanResult) error {
	sInfo := c.Conf.Servers[r.ServerName]
	if err := fillVulnByCpeNames(sInfo.CpeNames, r.ScannedCves); err != nil {
		return err
	}
	if err := fillCveDetail(r); err != nil {
		return err
	}
	return nil
}

// FillWithOval fetches OVAL database, and then set to fields.
func FillWithOval(r *models.ScanResult) (err error) {
	var ovalClient oval.Client
	var ovalFamily string

	// TODO
	switch r.Family {
	case c.Debian:
		ovalClient = oval.NewDebian()
		ovalFamily = c.Debian
	case c.Ubuntu:
		ovalClient = oval.NewUbuntu()
		ovalFamily = c.Ubuntu
	case c.RedHat:
		ovalClient = oval.NewRedhat()
		ovalFamily = c.RedHat
	case c.CentOS:
		ovalClient = oval.NewCentOS()
		//use RedHat's OVAL
		ovalFamily = c.RedHat
	case c.Oracle:
		ovalClient = oval.NewOracle()
		ovalFamily = c.Oracle
	case c.Amazon, c.Raspbian, c.FreeBSD:
		return nil
	default:
		return fmt.Errorf("OVAL for %s is not implemented yet", r.Family)
	}

	ok, err := ovalClient.CheckIfOvalFetched(ovalFamily, r.Release)
	if err != nil {
		return err
	}
	if !ok {
		major := strings.Split(r.Release, ".")[0]
		util.Log.Warnf("OVAL entries of %s %s are not found. It's recommended to use OVAL to improve scanning accuracy. For details, see https://github.com/kotakanbe/goval-dictionary#usage , Then report with --ovaldb-path or --ovaldb-url flag", ovalFamily, major)
		return nil
	}

	_, err = ovalClient.CheckIfOvalFresh(ovalFamily, r.Release)
	if err != nil {
		return err
	}

	if err := ovalClient.FillWithOval(r); err != nil {
		return err
	}
	return nil
}

func fillVulnByCpeNames(cpeNames []string, scannedVulns models.VulnInfos) error {
	for _, name := range cpeNames {
		details, err := CveClient.FetchCveDetailsByCpeName(name)
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
				scannedVulns[detail.CveID] = v
			}
		}
	}
	return nil
}
