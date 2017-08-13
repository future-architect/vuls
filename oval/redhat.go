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
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// RedHatBase is the base struct for RedHat and CentOS
type RedHatBase struct {
	Base
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o RedHatBase) FillWithOval(r *models.ScanResult) (err error) {
	var relatedDefs ovalResult
	if o.isFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(
			o.family, r.Release, r.Packages); err != nil {
			return err
		}
	}

	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		switch models.NewCveContentType(o.family) {
		case models.RedHat:
			if cont, ok := vuln.CveContents[models.RedHat]; ok {
				cont.SourceLink = "https://access.redhat.com/security/cve/" + cont.CveID
				vuln.CveContents[models.RedHat] = cont
			}
		case models.Oracle:
			if cont, ok := vuln.CveContents[models.Oracle]; ok {
				cont.SourceLink = fmt.Sprintf("https://linux.oracle.com/cve/%s.html", cont.CveID)
				vuln.CveContents[models.Oracle] = cont
			}
		}
	}
	return nil
}

func (o RedHatBase) update(r *models.ScanResult, defPacks defPacks) {
	ctype := models.NewCveContentType(o.family)
	for _, cve := range defPacks.def.Advisory.Cves {
		ovalContent := *o.convertToModel(cve.CveID, &defPacks.def)
		vinfo, ok := r.ScannedCves[cve.CveID]
		if !ok {
			util.Log.Debugf("%s is newly detected by OVAL", cve.CveID)
			vinfo = models.VulnInfo{
				CveID:       cve.CveID,
				Confidence:  models.OvalMatch,
				CveContents: models.NewCveContents(ovalContent),
			}
		} else {
			cveContents := vinfo.CveContents
			if _, ok := vinfo.CveContents[ctype]; ok {
				util.Log.Debugf("%s OVAL will be overwritten", cve.CveID)
			} else {
				util.Log.Debugf("%s also detected by OVAL", cve.CveID)
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
		r.ScannedCves[cve.CveID] = vinfo
	}
}

func (o RedHatBase) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}
		var refs []models.Reference
		for _, r := range def.References {
			refs = append(refs, models.Reference{
				Link:   r.RefURL,
				Source: r.Source,
				RefID:  r.RefID,
			})
		}

		score2, vec2 := o.parseCvss2(cve.Cvss2)
		score3, vec3 := o.parseCvss3(cve.Cvss3)

		severity := def.Advisory.Severity
		if cve.Impact != "" {
			severity = cve.Impact
		}

		return &models.CveContent{
			Type:         models.NewCveContentType(o.family),
			CveID:        cve.CveID,
			Title:        def.Title,
			Summary:      def.Description,
			Severity:     severity,
			Cvss2Score:   score2,
			Cvss2Vector:  vec2,
			Cvss3Score:   score3,
			Cvss3Vector:  vec3,
			References:   refs,
			CweID:        cve.Cwe,
			Published:    def.Advisory.Issued,
			LastModified: def.Advisory.Updated,
		}
	}
	return nil
}

// ParseCvss2 divide CVSSv2 string into score and vector
// 5/AV:N/AC:L/Au:N/C:N/I:N/A:P
func (o RedHatBase) parseCvss2(scoreVector string) (score float64, vector string) {
	var err error
	ss := strings.Split(scoreVector, "/")
	if 1 < len(ss) {
		if score, err = strconv.ParseFloat(ss[0], 64); err != nil {
			return 0, ""
		}
		return score, strings.Join(ss[1:len(ss)], "/")
	}
	return 0, ""
}

// ParseCvss3 divide CVSSv3 string into score and vector
// 5.6/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L
func (o RedHatBase) parseCvss3(scoreVector string) (score float64, vector string) {
	var err error
	ss := strings.Split(scoreVector, "/CVSS:3.0/")
	if 1 < len(ss) {
		if score, err = strconv.ParseFloat(ss[0], 64); err != nil {
			return 0, ""
		}
		return score, strings.Join(ss[1:len(ss)], "/")
	}
	return 0, ""
}

// RedHat is the interface for RedhatBase OVAL
type RedHat struct {
	RedHatBase
}

// NewRedhat creates OVAL client for Redhat
func NewRedhat() RedHat {
	return RedHat{
		RedHatBase{
			Base{
				family: config.RedHat,
			},
		},
	}
}

// CentOS is the interface for CentOS OVAL
type CentOS struct {
	RedHatBase
}

// NewCentOS creates OVAL client for CentOS
func NewCentOS() CentOS {
	return CentOS{
		RedHatBase{
			Base{
				family: config.CentOS,
			},
		},
	}
}

// Oracle is the interface for CentOS OVAL
type Oracle struct {
	RedHatBase
}

// NewOracle creates OVAL client for Oracle
func NewOracle() Oracle {
	return Oracle{
		RedHatBase{
			Base{
				family: config.Oracle,
			},
		},
	}
}
