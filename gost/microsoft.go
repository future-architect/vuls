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

package gost

import (
	"strings"

	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
)

// Microsoft is Gost client for windows
type Microsoft struct {
	Base
}

// FillWithGost fills cve information that has in Gost
func (ms Microsoft) FillWithGost(driver db.DB, r *models.ScanResult, _ bool) (nCVEs int, err error) {
	if driver == nil {
		return 0, nil
	}
	var cveIDs []string
	for cveID := range r.ScannedCves {
		cveIDs = append(cveIDs, cveID)
	}
	for cveID, msCve := range driver.GetMicrosoftMulti(cveIDs) {
		if _, ok := r.ScannedCves[cveID]; !ok {
			continue
		}
		cveCont := ms.ConvertToModel(&msCve)
		v, _ := r.ScannedCves[cveID]
		if v.CveContents == nil {
			v.CveContents = models.CveContents{}
		}
		v.CveContents[models.Microsoft] = *cveCont
		r.ScannedCves[cveID] = v
	}
	return len(cveIDs), nil
}

// ConvertToModel converts gost model to vuls model
func (ms Microsoft) ConvertToModel(cve *gostmodels.MicrosoftCVE) *models.CveContent {
	v3score := 0.0
	var v3Vector string
	for _, scoreSet := range cve.ScoreSets {
		if v3score < scoreSet.BaseScore {
			v3score = scoreSet.BaseScore
			v3Vector = scoreSet.Vector
		}
	}

	var v3Severity string
	for _, s := range cve.Severity {
		v3Severity = s.Description
	}

	var refs []models.Reference
	for _, r := range cve.References {
		if r.AttrType == "External" {
			refs = append(refs, models.Reference{Link: r.URL})
		}
	}

	var cwe []string
	if 0 < len(cve.CWE) {
		cwe = []string{cve.CWE}
	}

	option := map[string]string{}
	if 0 < len(cve.ExploitStatus) {
		option["exploit"] = cve.ExploitStatus
	}
	if 0 < len(cve.Workaround) {
		option["workaround"] = cve.Workaround
	}
	var kbids []string
	for _, kbid := range cve.KBIDs {
		kbids = append(kbids, kbid.KBID)
	}
	if 0 < len(kbids) {
		option["kbids"] = strings.Join(kbids, ",")
	}

	return &models.CveContent{
		Type:          models.Microsoft,
		CveID:         cve.CveID,
		Title:         cve.Title,
		Summary:       cve.Description,
		Cvss3Score:    v3score,
		Cvss3Vector:   v3Vector,
		Cvss3Severity: v3Severity,
		References:    refs,
		CweIDs:        cwe,
		Mitigation:    cve.Mitigation,
		Published:     cve.PublishDate,
		LastModified:  cve.LastUpdateDate,
		SourceLink:    "https://portal.msrc.microsoft.com/ja-jp/security-guidance/advisory/" + cve.CveID,
		Optional:      option,
	}
}
