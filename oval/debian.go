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
	"sort"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o DebianBase) FillWithOval(r *models.ScanResult) (err error) {
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
		switch models.NewCveContentType(o.family) {
		case models.Debian:
			if cont, ok := vuln.CveContents[models.Debian]; ok {
				cont.SourceLink = "https://security-tracker.debian.org/tracker/" + cont.CveID
				vuln.CveContents[models.Debian] = cont
			}
		case models.Ubuntu:
			if cont, ok := vuln.CveContents[models.Ubuntu]; ok {
				cont.SourceLink = "http://people.ubuntu.com/~ubuntu-security/cve/" + cont.CveID
				vuln.CveContents[models.Ubuntu] = cont
			}
		}
	}
	return nil
}

func (o DebianBase) update(r *models.ScanResult, defPacks defPacks) {
	ovalContent := *o.convertToModel(&defPacks.def)
	ovalContent.Type = models.NewCveContentType(o.family)
	vinfo, ok := r.ScannedCves[defPacks.def.Debian.CveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", defPacks.def.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:       defPacks.def.Debian.CveID,
			Confidence:  models.OvalMatch,
			CveContents: models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			util.Log.Debugf("%s OVAL will be overwritten",
				defPacks.def.Debian.CveID)
		} else {
			util.Log.Debugf("%s is also detected by OVAL",
				defPacks.def.Debian.CveID)
			cveContents = models.CveContents{}
		}
		if vinfo.Confidence.Score < models.OvalMatch.Score {
			vinfo.Confidence = models.OvalMatch
		}
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}

	// uniq(vinfo.PackNames + defPacks.actuallyAffectedPackNames)
	for _, name := range vinfo.PackageNames {
		defPacks.actuallyAffectedPackNames[name] = true
	}
	vinfo.PackageNames = defPacks.packNames()
	sort.Strings(vinfo.PackageNames)
	r.ScannedCves[defPacks.def.Debian.CveID] = vinfo
}

func (o DebianBase) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	var refs []models.Reference
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	return &models.CveContent{
		CveID:      def.Debian.CveID,
		Title:      def.Title,
		Summary:    def.Description,
		Severity:   def.Advisory.Severity,
		References: refs,
	}
}

// Debian is the interface for Debian OVAL
type Debian struct {
	DebianBase
}

// NewDebian creates OVAL client for Debian
func NewDebian() Debian {
	return Debian{
		DebianBase{
			Base{
				family: config.Debian,
			},
		},
	}
}

// Ubuntu is the interface for Debian OVAL
type Ubuntu struct {
	DebianBase
}

// NewUbuntu creates OVAL client for Debian
func NewUbuntu() Ubuntu {
	return Ubuntu{
		DebianBase{
			Base{
				family: config.Ubuntu,
			},
		},
	}
}
