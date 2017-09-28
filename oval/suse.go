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
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// SUSE is the struct of SUSE Linux
type SUSE struct {
	Base
}

// NewSUSE creates OVAL client for SUSE
func NewSUSE() SUSE {
	// TODO implement other family
	return SUSE{
		Base{
			family: config.SUSEEnterpriseServer,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o SUSE) FillWithOval(r *models.ScanResult) (err error) {
	var relatedDefs ovalResult
	if o.isFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(o.family, r.Release, r.Packages); err != nil {
			return err
		}
	}
	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.SUSE]; ok {
			cont.SourceLink = "https://security-tracker.debian.org/tracker/" + cont.CveID
			vuln.CveContents[models.SUSE] = cont
		}
	}
	return nil
}

func (o SUSE) update(r *models.ScanResult, defPacks defPacks) {
	ovalContent := *o.convertToModel(&defPacks.def)
	ovalContent.Type = models.NewCveContentType(o.family)
	vinfo, ok := r.ScannedCves[defPacks.def.Title]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", defPacks.def.Title)
		vinfo = models.VulnInfo{
			CveID:       defPacks.def.Title,
			Confidence:  models.OvalMatch,
			CveContents: models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			util.Log.Debugf("%s OVAL will be overwritten", defPacks.def.Title)
		} else {
			util.Log.Debugf("%s is also detected by OVAL", defPacks.def.Title)
			cveContents = models.CveContents{}
		}
		if vinfo.Confidence.Score < models.OvalMatch.Score {
			vinfo.Confidence = models.OvalMatch
		}
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}

	// uniq(vinfo.PackNames + defPacks.actuallyAffectedPackNames)
	for _, pack := range vinfo.AffectedPackages {
		defPacks.actuallyAffectedPackNames[pack.Name] = true
	}
	vinfo.AffectedPackages = defPacks.toPackStatuses(r.Family, r.Packages)
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[defPacks.def.Title] = vinfo
}

func (o SUSE) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	var refs []models.Reference
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	return &models.CveContent{
		CveID:      def.Title,
		Title:      def.Title,
		Summary:    def.Description,
		References: refs,
	}
}
