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

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o DebianBase) FillWithOval(r *models.ScanResult) (err error) {
	var defs []ovalmodels.Definition
	if o.isFetchViaHTTP() {
		if defs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return err
		}
	} else {
		if defs, err = getDefsByPackNameFromOvalDB(o.family, r.Release, r.Packages); err != nil {
			return err
		}
	}

	for _, def := range defs {
		o.update(r, &def)
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

func (o DebianBase) update(r *models.ScanResult, definition *ovalmodels.Definition) {
	ovalContent := *o.convertToModel(definition)
	ovalContent.Type = models.NewCveContentType(o.family)
	vinfo, ok := r.ScannedCves[definition.Debian.CveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", definition.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:        definition.Debian.CveID,
			Confidence:   models.OvalMatch,
			PackageNames: getPackages(r, definition),
			CveContents:  models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			util.Log.Debugf("%s will be updated by OVAL", definition.Debian.CveID)
		} else {
			util.Log.Debugf("%s is also detected by OVAL", definition.Debian.CveID)
			cveContents = models.CveContents{}
		}
		if vinfo.Confidence.Score < models.OvalMatch.Score {
			vinfo.Confidence = models.OvalMatch
		}
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}
	r.ScannedCves[definition.Debian.CveID] = vinfo
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
