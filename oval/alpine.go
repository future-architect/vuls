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

package oval

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/kotakanbe/goval-dictionary/db"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
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
func (o Alpine) FillWithOval(driver db.DB, r *models.ScanResult) (err error) {
	var relatedDefs ovalResult
	if o.isFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return err
		}
	}
	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	return nil
}

func (o Alpine) update(r *models.ScanResult, defPacks defPacks) {
	ovalContent := *o.convertToModel(&defPacks.def)
	cveID := defPacks.def.Advisory.Cves[0].CveID
	vinfo, ok := r.ScannedCves[cveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", cveID)
		vinfo = models.VulnInfo{
			CveID:       cveID,
			Confidence:  models.OvalMatch,
			CveContents: models.NewCveContents(ovalContent),
		}
	}

	vinfo.AffectedPackages = defPacks.toPackStatuses(r.Family)
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[cveID] = vinfo
}

func (o Alpine) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	return &models.CveContent{
		CveID: def.Advisory.Cves[0].CveID,
	}
}
