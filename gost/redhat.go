//go:build !scanner

package gost

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	gostmodels "github.com/vulsio/gost/models"
)

// RedHat is Gost client for RedHat family linux
type RedHat struct {
	Base
}

func (red RedHat) fillCvesWithRedHatAPI(r *models.ScanResult) error {
	cveIDs := []string{}
	for cveID, vuln := range r.ScannedCves {
		if _, ok := vuln.CveContents[models.RedHatAPI]; ok {
			continue
		}
		cveIDs = append(cveIDs, cveID)
	}

	if red.driver == nil {
		prefix, err := util.URLPathJoin(red.baseURL, "redhat", "cves")
		if err != nil {
			return err
		}
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
			red.setFixedCveToScanResult(&redCve, r)
		}
	} else {
		redCves, err := red.driver.GetRedhatMulti(cveIDs)
		if err != nil {
			return err
		}
		for _, redCve := range redCves {
			if len(redCve.Name) == 0 {
				continue
			}
			red.setFixedCveToScanResult(&redCve, r)
		}
	}

	return nil
}

func (red RedHat) setFixedCveToScanResult(cve *gostmodels.RedhatCVE, r *models.ScanResult) {
	cveCont, mitigations := red.ConvertToModel(cve)
	v, ok := r.ScannedCves[cveCont.CveID]
	if ok {
		if v.CveContents == nil {
			v.CveContents = models.NewCveContents(*cveCont)
		} else {
			v.CveContents[models.RedHatAPI] = []models.CveContent{*cveCont}
		}
	} else {
		v = models.VulnInfo{
			CveID:       cveCont.CveID,
			CveContents: models.NewCveContents(*cveCont),
			Confidences: models.Confidences{models.RedHatAPIMatch},
		}
	}
	v.Mitigations = append(v.Mitigations, mitigations...)
	r.ScannedCves[cveCont.CveID] = v
}

func (red RedHat) parseCwe(str string) (cwes []string) {
	if str != "" {
		s := strings.ReplaceAll(str, "(", "|")
		s = strings.ReplaceAll(s, ")", "|")
		s = strings.ReplaceAll(s, "->", "|")
		for s := range strings.SplitSeq(s, "|") {
			if s != "" {
				cwes = append(cwes, s)
			}
		}
	}
	return
}

// ConvertToModel converts gost model to vuls model
func (red RedHat) ConvertToModel(cve *gostmodels.RedhatCVE) (*models.CveContent, []models.Mitigation) {
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

	refs := []models.Reference{}
	for _, r := range cve.References {
		refs = append(refs, models.Reference{Link: r.Reference})
	}

	vendorURL := "https://access.redhat.com/security/cve/" + cve.Name
	mitigations := []models.Mitigation{}
	if cve.Mitigation != "" {
		mitigations = []models.Mitigation{
			{
				CveContentType: models.RedHatAPI,
				Mitigation:     cve.Mitigation,
				URL:            vendorURL,
			},
		}
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
		Published:     cve.PublicDate,
		SourceLink:    vendorURL,
	}, mitigations
}
