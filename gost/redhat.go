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
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
)

// RedHat is Gost client for RedHat family linux
type RedHat struct {
	Base
}

// FillWithGost fills cve information that has in Gost
func (red RedHat) FillWithGost(driver db.DB, r *models.ScanResult, ignoreWillNotFix bool) (nCVEs int, err error) {
	if nCVEs, err = red.fillUnfixed(driver, r, ignoreWillNotFix); err != nil {
		return 0, err
	}
	return nCVEs, red.fillFixed(driver, r)
}

func (red RedHat) fillFixed(driver db.DB, r *models.ScanResult) error {
	var cveIDs []string
	for cveID, vuln := range r.ScannedCves {
		if _, ok := vuln.CveContents[models.RedHatAPI]; ok {
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}

	if config.Conf.Gost.IsFetchViaHTTP() {
		prefix, _ := util.URLPathJoin(config.Conf.Gost.URL,
			"redhat", "cves")
		responses, err := getCvesViaHTTP(cveIDs, prefix)
		if err != nil {
			return err
		}
		for _, res := range responses {
			redCve := gostmodels.RedhatCVE{}
			if err := json.Unmarshal([]byte(res.json), &redCve); err != nil {
				return err
			}
			if redCve.ID == 0 {
				continue
			}
			cveCont := red.ConvertToModel(&redCve)
			v, ok := r.ScannedCves[res.request.cveID]
			if ok {
				if v.CveContents == nil {
					v.CveContents = models.NewCveContents(*cveCont)
				} else {
					v.CveContents[models.RedHatAPI] = *cveCont
				}
			} else {
				v = models.VulnInfo{
					CveID:       cveCont.CveID,
					CveContents: models.NewCveContents(*cveCont),
					Confidences: models.Confidences{models.RedHatAPIMatch},
				}
			}
			r.ScannedCves[res.request.cveID] = v
		}
	} else {
		if driver == nil {
			return nil
		}
		for cveID, redCve := range driver.GetRedhatMulti(cveIDs) {
			if redCve.ID == 0 {
				continue
			}
			cveCont := red.ConvertToModel(&redCve)
			v, ok := r.ScannedCves[cveID]
			if ok {
				if v.CveContents == nil {
					v.CveContents = models.NewCveContents(*cveCont)
				} else {
					v.CveContents[models.RedHatAPI] = *cveCont
				}
			} else {
				v = models.VulnInfo{
					CveID:       cveCont.CveID,
					CveContents: models.NewCveContents(*cveCont),
					Confidences: models.Confidences{models.RedHatAPIMatch},
				}
			}
			r.ScannedCves[cveID] = v
		}
	}

	return nil
}

func (red RedHat) fillUnfixed(driver db.DB, r *models.ScanResult, ignoreWillNotFix bool) (nCVEs int, err error) {
	if config.Conf.Gost.IsFetchViaHTTP() {
		prefix, _ := util.URLPathJoin(config.Conf.Gost.URL,
			"redhat", major(r.Release), "pkgs")
		responses, err := getAllUnfixedCvesViaHTTP(r, prefix)
		if err != nil {
			return 0, err
		}
		for _, res := range responses {
			// CVE-ID: RedhatCVE
			cves := map[string]gostmodels.RedhatCVE{}
			if err := json.Unmarshal([]byte(res.json), &cves); err != nil {
				return 0, err
			}

			for _, cve := range cves {
				cveCont := red.ConvertToModel(&cve)
				v, ok := r.ScannedCves[cve.Name]
				if ok {
					if v.CveContents == nil {
						v.CveContents = models.NewCveContents(*cveCont)
					} else {
						v.CveContents[models.RedHatAPI] = *cveCont
					}
				} else {
					v = models.VulnInfo{
						CveID:       cveCont.CveID,
						CveContents: models.NewCveContents(*cveCont),
						Confidences: models.Confidences{models.RedHatAPIMatch},
					}
					nCVEs++
				}
				pkgStats := red.mergePackageStates(v,
					cve.PackageState, r.Packages, r.Release)
				if 0 < len(pkgStats) {
					v.AffectedPackages = pkgStats
					r.ScannedCves[cve.Name] = v
				}
			}
		}
	} else {
		if driver == nil {
			return 0, nil
		}
		for _, pack := range r.Packages {
			// CVE-ID: RedhatCVE
			cves := map[string]gostmodels.RedhatCVE{}
			cves = driver.GetUnfixedCvesRedhat(major(r.Release), pack.Name, ignoreWillNotFix)
			for _, cve := range cves {
				cveCont := red.ConvertToModel(&cve)
				v, ok := r.ScannedCves[cve.Name]
				if ok {
					if v.CveContents == nil {
						v.CveContents = models.NewCveContents(*cveCont)
					} else {
						v.CveContents[models.RedHatAPI] = *cveCont
					}
				} else {
					v = models.VulnInfo{
						CveID:       cveCont.CveID,
						CveContents: models.NewCveContents(*cveCont),
						Confidences: models.Confidences{models.RedHatAPIMatch},
					}
					nCVEs++
				}

				pkgStats := red.mergePackageStates(v,
					cve.PackageState, r.Packages, r.Release)
				if 0 < len(pkgStats) {
					v.AffectedPackages = pkgStats
					r.ScannedCves[cve.Name] = v
				}
			}
		}
	}
	return nCVEs, nil
}

func (red RedHat) mergePackageStates(v models.VulnInfo, ps []gostmodels.RedhatPackageState, installed models.Packages, release string) (pkgStats models.PackageFixStatuses) {
	pkgStats = v.AffectedPackages
	for _, pstate := range ps {
		if pstate.Cpe !=
			"cpe:/o:redhat:enterprise_linux:"+major(release) {
			return
		}

		if !(pstate.FixState == "Will not fix" ||
			pstate.FixState == "Fix deferred" ||
			pstate.FixState == "Affected") {
			return
		}

		if _, ok := installed[pstate.PackageName]; !ok {
			return
		}

		notFixedYet := false
		switch pstate.FixState {
		case "Will not fix", "Fix deferred", "Affected":
			notFixedYet = true
		}

		pkgStats = pkgStats.Store(models.PackageFixStatus{
			Name:        pstate.PackageName,
			FixState:    pstate.FixState,
			NotFixedYet: notFixedYet,
		})
	}
	return
}

func (red RedHat) parseCwe(str string) (cwes []string) {
	if str != "" {
		s := strings.Replace(str, "(", "|", -1)
		s = strings.Replace(s, ")", "|", -1)
		s = strings.Replace(s, "->", "|", -1)
		for _, s := range strings.Split(s, "|") {
			if s != "" {
				cwes = append(cwes, s)
			}
		}
	}
	return
}

// ConvertToModel converts gost model to vuls model
func (red RedHat) ConvertToModel(cve *gostmodels.RedhatCVE) *models.CveContent {
	cwes := red.parseCwe(cve.Cwe)

	details := []string{}
	for _, detail := range cve.Details {
		details = append(details, detail.Detail)
	}

	v2score := 0.0
	if cve.Cvss.CvssBaseScore != "" {
		v2score, _ = strconv.ParseFloat(cve.Cvss.CvssBaseScore, 64)
	}
	v2severity := ""
	if v2score != 0 {
		v2severity = cve.ThreatSeverity
	}

	v3score := 0.0
	if cve.Cvss3.Cvss3BaseScore != "" {
		v3score, _ = strconv.ParseFloat(cve.Cvss3.Cvss3BaseScore, 64)
	}
	v3severity := ""
	if v3score != 0 {
		v3severity = cve.ThreatSeverity
	}

	var refs []models.Reference
	for _, r := range cve.References {
		refs = append(refs, models.Reference{Link: r.Reference})
	}

	return &models.CveContent{
		Type:          models.RedHatAPI,
		CveID:         cve.Name,
		Title:         cve.Bugzilla.Description,
		Summary:       strings.Join(details, "\n"),
		Cvss2Score:    v2score,
		Cvss2Vector:   cve.Cvss.CvssScoringVector,
		Cvss2Severity: v2severity,
		Cvss3Score:    v3score,
		Cvss3Vector:   cve.Cvss3.Cvss3ScoringVector,
		Cvss3Severity: v3severity,
		References:    refs,
		CweIDs:        cwes,
		Mitigation:    cve.Mitigation,
		Published:     cve.PublicDate,
		SourceLink:    "https://access.redhat.com/security/cve/" + cve.Name,
	}
}
