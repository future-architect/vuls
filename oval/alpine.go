/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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

package oval

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/kotakanbe/goval-dictionary/db"
)

// Alpine is the struct of Alpine Linux
type Alpine struct {
	Base
}

// NewAlpine creates OVAL client for SUSE
func NewAlpine() Alpine {
	return Alpine{
		Base{
			family: config.Alpine,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Alpine) FillWithOval(driver db.DB, r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if config.Conf.OvalDict.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return 0, err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
		}
	}
	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	return len(relatedDefs.entries), nil
}

func (o Alpine) update(r *models.ScanResult, defPacks defPacks) {
	cveID := defPacks.def.Advisory.Cves[0].CveID
	vinfo, ok := r.ScannedCves[cveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", cveID)
		vinfo = models.VulnInfo{
			CveID:       cveID,
			Confidences: []models.Confidence{models.OvalMatch},
		}
	}

	vinfo.AffectedPackages = defPacks.toPackStatuses()
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[cveID] = vinfo
}
