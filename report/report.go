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
	"os"

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
	for _, r := range rs {
		if c.Conf.RefreshCve || needToRefreshCve(r) {
			if err := fillCveInfo(&r); err != nil {
				return nil, err
			}
			r.Lang = c.Conf.Lang
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

	//TODO remove debug code
	//  for _, r := range filled {
	//      pp.Printf("filled: %d\n", len(r.ScannedCves))
	//  }

	filtered := []models.ScanResult{}
	for _, r := range filled {
		filtered = append(filtered, r.FilterByCvssOver(c.Conf.CvssScoreOver))
	}

	//TODO remove debug code
	//  for _, r := range filtered {
	//      pp.Printf("filtered: %d\n", len(r.ScannedCves))
	//  }

	return filtered, nil
}

func fillCveInfo(r *models.ScanResult) error {
	util.Log.Debugf("need to refresh")
	if c.Conf.CveDBType == "sqlite3" {
		if c.Conf.CveDBURL == "" {
			if _, err := os.Stat(c.Conf.CveDBPath); os.IsNotExist(err) {
				return fmt.Errorf("SQLite3 DB(CVE-Dictionary) is not exist: %s",
					c.Conf.CveDBPath)
			}
		}
		if c.Conf.OvalDBURL == "" {
			if _, err := os.Stat(c.Conf.OvalDBPath); os.IsNotExist(err) {
				//TODO Warning
				return fmt.Errorf("SQLite3 DB(OVAL-Dictionary) is not exist: %s",
					c.Conf.OvalDBPath)
			}
		}
	}

	util.Log.Debugf("Fill CVE detailed information with OVAL")
	if err := fillWithOvalDB(r); err != nil {
		return fmt.Errorf("Failed to fill OVAL information: %s", err)
	}

	util.Log.Debugf("Fill CVE detailed information with CVE-DB")
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
		nvd := r.ConvertNvdToModel(d.CveID, d.Nvd)
		jvn := r.ConvertJvnToModel(d.CveID, d.Jvn)
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

func fillWithOvalDB(r *models.ScanResult) error {
	var ovalClient oval.Client
	switch r.Family {
	case "debian":
		ovalClient = oval.NewDebian()
	case "ubuntu":
		ovalClient = oval.NewUbuntu()
	case "rhel":
		ovalClient = oval.NewRedhat()
	case "centos":
		ovalClient = oval.NewCentOS()
	case "amazon", "oraclelinux", "Raspbian", "FreeBSD":
		//TODO implement OracleLinux
		return nil
	default:
		return fmt.Errorf("Oval %s is not implemented yet", r.Family)
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
