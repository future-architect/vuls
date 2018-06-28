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
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
	"github.com/parnurzeal/gorequest"
)

// Client is the interface of OVAL client.
type Client interface {
	FillWithGost(db.DB, *models.ScanResult) error

	//TODO implement
	// CheckHTTPHealth() error
	// CheckIfGostFetched checks if Gost entries are fetched
	// CheckIfGostFetched(db.DB, string, string) (bool, error)
	// CheckIfGostFresh(db.DB, string, string) (bool, error)
}

// NewClient make Client by family
func NewClient(family string) Client {
	switch family {
	case config.RedHat, config.CentOS:
		return RedHat{}
	default:
		return Pseudo{}
	}
}

// Base is a base struct
type Base struct {
	family string
}

// CheckHTTPHealth do health check
func (b Base) CheckHTTPHealth() error {
	if !b.isFetchViaHTTP() {
		return nil
	}

	url := fmt.Sprintf("%s/health", config.Conf.GostDBURL)
	var errs []error
	var resp *http.Response
	resp, _, errs = gorequest.New().Get(url).End()
	//  resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return fmt.Errorf("Failed to request to OVAL server. url: %s, errs: %v",
			url, errs)
	}
	return nil
}

// CheckIfGostFetched checks if oval entries are in DB by family, release.
func (b Base) CheckIfGostFetched(driver db.DB, osFamily string) (fetched bool, err error) {
	//TODO
	return true, nil
}

// CheckIfGostFresh checks if oval entries are fresh enough
func (b Base) CheckIfGostFresh(driver db.DB, osFamily string) (ok bool, err error) {
	//TODO
	return true, nil
}

func (b Base) isFetchViaHTTP() bool {
	// Default value of OvalDBType is sqlite3
	return config.Conf.GostDBURL != "" && config.Conf.GostDBType == "sqlite3"
}

// RedHat is Gost client for RedHat family linux
type RedHat struct {
	Base
}

// FillWithGost fills cve information that has in Gost
func (red RedHat) FillWithGost(driver db.DB, r *models.ScanResult) error {
	for _, pack := range r.Packages {
		cves, err := driver.GetUnfixedCvesRedhat(major(r.Release), pack.Name)
		if err != nil {
			return err
		}

		for _, cve := range cves {
			cveCont := red.convertToModel(cve)
			v, ok := r.ScannedCves[cve.Name]
			if ok {
				v.CveContents[models.RedHatAPI] = *cveCont
			} else {
				v = models.VulnInfo{
					CveID:       cveCont.CveID,
					CveContents: models.NewCveContents(*cveCont),
					Confidences: models.Confidences{models.RedHatAPIMatch},
				}
			}

			r.ScannedCves[cve.Name] = *red.setPackageStates(&v,
				cve.PackageState, r.Packages, r.Release)
		}
	}
	return nil
}

func (red RedHat) setPackageStates(v *models.VulnInfo, ps []gostmodels.RedhatPackageState, installed models.Packages, release string) *models.VulnInfo {
	for _, pstate := range ps {
		if pstate.Cpe !=
			"cpe:/o:redhat:enterprise_linux:"+major(release) {
			return v
		}

		if !(pstate.FixState == "Will not fix" ||
			pstate.FixState == "Fix deferred") {
			return v
		}

		if _, ok := installed[pstate.PackageName]; !ok {
			return v
		}

		notFixedYet := false
		switch pstate.FixState {
		case "Will not fix", "Fix deferred":
			notFixedYet = true
		}

		v.AffectedPackages = v.AffectedPackages.Store(models.PackageStatus{
			Name:        pstate.PackageName,
			FixState:    pstate.FixState,
			NotFixedYet: notFixedYet,
		})
	}
	return v
}

func (red RedHat) convertToModel(cve *gostmodels.RedhatCVE) *models.CveContent {
	cwes := []string{}
	s := strings.TrimPrefix(cve.Cwe, "(")
	s = strings.TrimSuffix(s, ")")
	if strings.Contains(cve.Cwe, "|") {
		cwes = strings.Split(cve.Cwe, "|")
	} else {
		cwes = append(strings.Split(s, "->"))
	}

	details := []string{}
	for _, detail := range cve.Details {
		details = append(details, detail.Detail)
	}

	v2score := 0.0
	if cve.Cvss.CvssBaseScore != "" {
		v2score, _ = strconv.ParseFloat(cve.Cvss.CvssBaseScore, 32)
	}
	v2severity := ""
	if v2score != 0 {
		v2severity = cve.ThreatSeverity
	}

	v3score := 0.0
	if cve.Cvss3.Cvss3BaseScore != "" {
		v3score, _ = strconv.ParseFloat(cve.Cvss3.Cvss3BaseScore, 32)
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

// Pseudo is Gost client except for RedHat family and Debian
type Pseudo struct {
	Base
}

// FillWithGost fills cve information that has in Gost
func (pse Pseudo) FillWithGost(driver db.DB, r *models.ScanResult) error {
	return nil
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
