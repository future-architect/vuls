// +build !scanner

package gost

import (
	"strings"

	"github.com/future-architect/vuls/models"
	gostmodels "github.com/knqyf263/gost/models"
)

// Microsoft is Gost client for windows
type Microsoft struct {
	Base
}

// DetectCVEs fills cve information that has in Gost
func (ms Microsoft) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	if ms.DBDriver.DB == nil {
		return 0, nil
	}
	cveIDs := []string{}
	for cveID := range r.ScannedCves {
		cveIDs = append(cveIDs, cveID)
	}
	for cveID, msCve := range ms.DBDriver.DB.GetMicrosoftMulti(cveIDs) {
		if _, ok := r.ScannedCves[cveID]; !ok {
			continue
		}
		cveCont, mitigations := ms.ConvertToModel(&msCve)
		v, _ := r.ScannedCves[cveID]
		if v.CveContents == nil {
			v.CveContents = models.CveContents{}
		}
		v.CveContents[models.Microsoft] = *cveCont
		v.Mitigations = append(v.Mitigations, mitigations...)
		r.ScannedCves[cveID] = v
	}
	return len(cveIDs), nil
}

// ConvertToModel converts gost model to vuls model
func (ms Microsoft) ConvertToModel(cve *gostmodels.MicrosoftCVE) (*models.CveContent, []models.Mitigation) {
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
		// TODO: CVE-2020-0739
		// "exploit_status": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely;Older Software Release:Exploitation Less Likely;DOS:N/A",
		option["exploit"] = cve.ExploitStatus
	}
	kbids := []string{}
	for _, kbid := range cve.KBIDs {
		kbids = append(kbids, kbid.KBID)
	}
	if 0 < len(kbids) {
		option["kbids"] = strings.Join(kbids, ",")
	}

	vendorURL := "https://msrc.microsoft.com/update-guide/vulnerability/" + cve.CveID
	mitigations := []models.Mitigation{}
	if cve.Mitigation != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Mitigation,
			URL:            vendorURL,
		})
	}
	if cve.Workaround != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Workaround,
			URL:            vendorURL,
		})
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
		Published:     cve.PublishDate,
		LastModified:  cve.LastUpdateDate,
		SourceLink:    vendorURL,
		Optional:      option,
	}, mitigations
}
