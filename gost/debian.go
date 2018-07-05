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

package gost

import (
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
)

// Debian is Gost client for Debian GNU/Linux
type Debian struct {
	Base
}

// FillWithGost fills cve information that has in Gost
func (deb Debian) FillWithGost(driver db.DB, r *models.ScanResult) error {
	for _, pack := range r.Packages {
		cves := driver.GetUnfixedCvesDebian(major(r.Release), pack.Name)
		for _, cve := range cves {
			cveCont := deb.convertToModel(&cve)
			v, ok := r.ScannedCves[cve.CveID]
			if ok {
				v.CveContents[models.DebianSecurityTracker] = *cveCont
			} else {
				v = models.VulnInfo{
					CveID:       cveCont.CveID,
					CveContents: models.NewCveContents(*cveCont),
					Confidences: models.Confidences{models.DebianSecurityTrackerMatch},
				}
			}

			v.AffectedPackages = v.AffectedPackages.Store(models.PackageStatus{
				Name:        pack.Name,
				FixState:    "open",
				NotFixedYet: true,
			})
			r.ScannedCves[cve.CveID] = v
		}
	}
	return nil
}

func (deb Debian) convertToModel(cve *gostmodels.DebianCVE) *models.CveContent {
	severity := ""
	for _, p := range cve.Package {
		for _, r := range p.Release {
			severity = r.Urgency
			break
		}
	}
	//TODO sccope
	return &models.CveContent{
		Type:          models.DebianSecurityTracker,
		CveID:         cve.CveID,
		Summary:       cve.Description,
		Cvss2Severity: severity,
		Cvss3Severity: severity,
		SourceLink:    "https://security-tracker.debian.org/tracker/" + cve.CveID,
	}
}
