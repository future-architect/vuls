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
	"encoding/json"
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
)

// Debian is Gost client for Debian GNU/Linux
type Debian struct {
	Base
}

type packCves struct {
	packName  string
	isSrcPack bool
	cves      []models.CveContent
}

// FillWithGost fills cve information that has in Gost
func (deb Debian) FillWithGost(driver db.DB, r *models.ScanResult) error {
	linuxImage := "linux-image-" + r.RunningKernel.Release
	// Add linux and set the version of running kernel to search OVAL.
	if r.Container.ContainerID == "" {
		newVer := ""
		if p, ok := r.Packages[linuxImage]; ok {
			newVer = p.NewVersion
		}
		r.Packages["linux"] = models.Package{
			Name:       "linux",
			Version:    r.RunningKernel.Version,
			NewVersion: newVer,
		}
	}

	packCvesList := []packCves{}
	if deb.isFetchViaHTTP() {
		url, _ := util.URLPathJoin(config.Conf.GostDBURL, "debian", major(r.Release), "pkgs")
		responses, err := getUnfixedCvesViaHTTP(r, url)
		if err != nil {
			return err
		}

		for _, res := range responses {
			debCves := map[string]gostmodels.DebianCVE{}
			if err := json.Unmarshal([]byte(res.json), &debCves); err != nil {
				return err
			}
			cves := []models.CveContent{}
			for _, debcve := range debCves {
				cves = append(cves, *deb.convertToModel(&debcve))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  res.request.packName,
				isSrcPack: res.request.isSrcPack,
				cves:      cves,
			})
		}
	} else {
		if driver == nil {
			return fmt.Errorf("Gost DB Driver is nil")
		}
		for _, pack := range r.Packages {
			cveDebs := driver.GetUnfixedCvesDebian(major(r.Release), pack.Name)
			cves := []models.CveContent{}
			for _, cveDeb := range cveDebs {
				cves = append(cves, *deb.convertToModel(&cveDeb))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: false,
				cves:      cves,
			})
		}

		// SrcPack
		for _, pack := range r.SrcPackages {
			cveDebs := driver.GetUnfixedCvesDebian(major(r.Release), pack.Name)
			cves := []models.CveContent{}
			for _, cveDeb := range cveDebs {
				cves = append(cves, *deb.convertToModel(&cveDeb))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: true,
				cves:      cves,
			})
		}
	}

	delete(r.Packages, "linux")

	for _, p := range packCvesList {
		for _, cve := range p.cves {
			v, ok := r.ScannedCves[cve.CveID]
			if ok {
				v.CveContents[models.DebianSecurityTracker] = cve
			} else {
				v = models.VulnInfo{
					CveID:       cve.CveID,
					CveContents: models.NewCveContents(cve),
					Confidences: models.Confidences{models.DebianSecurityTrackerMatch},
				}
			}

			names := []string{}
			if p.isSrcPack {
				if srcPack, ok := r.SrcPackages[p.packName]; ok {
					for _, binName := range srcPack.BinaryNames {
						if _, ok := r.Packages[binName]; ok {
							names = append(names, binName)
						}
					}
				}
			} else {
				if p.packName == "linux" {
					names = append(names, linuxImage)
				} else {
					names = append(names, p.packName)
				}
			}

			for _, name := range names {
				v.AffectedPackages = v.AffectedPackages.Store(models.PackageStatus{
					Name:        name,
					FixState:    "open",
					NotFixedYet: true,
				})
			}
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
	return &models.CveContent{
		Type:          models.DebianSecurityTracker,
		CveID:         cve.CveID,
		Summary:       cve.Description,
		Cvss2Severity: severity,
		Cvss3Severity: severity,
		SourceLink:    "https://security-tracker.debian.org/tracker/" + cve.CveID,
		Optional: map[string]string{
			"attack range": cve.Scope,
		},
	}
}
