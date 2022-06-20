//go:build !scanner
// +build !scanner

package gost

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/inconshreveable/log15"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/models"
	gostmodels "github.com/vulsio/gost/models"
)

// Microsoft is Gost client for windows
type Microsoft struct {
	Base
}

var kbIDPattern = regexp.MustCompile(`KB(\d{6,7})`)

// DetectCVEs fills cve information that has in Gost
func (ms Microsoft) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	if ms.driver == nil {
		return 0, nil
	}

	var osName string
	if n, ok := r.Optional["OSName"]; ok {
		switch n.(type) {
		case string:
			osName = n.(string)
		default:
			log15.Warn("This Windows has wrong type option(OSName).", "UUID", r.ServerUUID)
		}
	}

	var products []string
	if _, ok := r.Optional["InstalledProducts"]; ok {
		switch ps := r.Optional["InstalledProducts"].(type) {
		case []interface{}:
			for _, p := range ps {
				products = append(products, p.(string))
			}
		case nil:
			log15.Warn("This Windows has no option(InstalledProducts).", "UUID", r.ServerUUID)
		}
	}

	applied, unapplied := map[string]struct{}{}, map[string]struct{}{}
	if _, ok := r.Optional["KBID"]; ok {
		switch kbIDs := r.Optional["KBID"].(type) {
		case []interface{}:
			for _, kbID := range kbIDs {
				formattedKBID := kbID.(string)
				if !strings.HasPrefix(formattedKBID, "KB") {
					formattedKBID = fmt.Sprintf("KB%s", formattedKBID)
				}
				unapplied[formattedKBID] = struct{}{}
			}
		case nil:
			log15.Warn("This windows server has no option(KBID).", "UUID", r.ServerUUID)
		}

		for _, pkg := range r.Packages {
			matches := kbIDPattern.FindAllStringSubmatch(pkg.Name, -1)
			for _, match := range matches {
				formattedKBID := match[1]
				if !strings.HasPrefix(formattedKBID, "KB") {
					formattedKBID = fmt.Sprintf("KB%s", formattedKBID)
				}
				applied[formattedKBID] = struct{}{}
			}
		}
	} else {
		switch kbIDs := r.Optional["AppliedKBID"].(type) {
		case []interface{}:
			for _, kbID := range kbIDs {
				formattedKBID := kbID.(string)
				if !strings.HasPrefix(formattedKBID, "KB") {
					formattedKBID = fmt.Sprintf("KB%s", formattedKBID)
				}
				applied[formattedKBID] = struct{}{}
			}
		case nil:
			log15.Warn("This windows server has no option(AppliedKBID).", "UUID", r.ServerUUID)
		}

		switch kbIDs := r.Optional["UnappliedKBID"].(type) {
		case []interface{}:
			for _, kbID := range kbIDs {
				formattedKBID := kbID.(string)
				if !strings.HasPrefix(formattedKBID, "KB") {
					formattedKBID = fmt.Sprintf("KB%s", formattedKBID)
				}
				unapplied[formattedKBID] = struct{}{}
			}
		case nil:
			log15.Warn("This windows server has no option(UnappliedKBID).", "UUID", r.ServerUUID)
		}
	}

	cves, err := ms.driver.GetCvesByMicrosoftKBID(osName, products, maps.Keys(applied), maps.Keys(unapplied))
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect CVEs. err: %w", err)
	}

	for cveID, cve := range cves {
		cveCont, mitigations := ms.ConvertToModel(&cve)
		advisories := []models.DistroAdvisory{}
		for _, p := range cve.Products {
			for _, kb := range p.KBs {
				adv := models.DistroAdvisory{
					Description: "Microsoft Knowledge Base",
				}
				if kbIDPattern.MatchString(kb.Article) {
					adv.AdvisoryID = fmt.Sprintf("KB%s", kb.Article)
				} else {
					adv.AdvisoryID = kb.Article
				}
				advisories = append(advisories, adv)
			}
		}

		r.ScannedCves[cveID] = models.VulnInfo{
			CveID:            cveID,
			Confidences:      models.Confidences{models.WindowsUpdateSearch},
			DistroAdvisories: advisories,
			CveContents:      models.NewCveContents(*cveCont),
			Mitigations:      mitigations,
		}
	}
	return len(cves), nil
}

// ConvertToModel converts gost model to vuls model
func (ms Microsoft) ConvertToModel(cve *gostmodels.MicrosoftCVE) (*models.CveContent, []models.Mitigation) {
	slices.SortFunc(cve.Products, func(i, j gostmodels.MicrosoftProduct) bool {
		return i.ScoreSet.Vector < j.ScoreSet.Vector
	})

	v3score := 0.0
	var v3Vector string
	for _, p := range cve.Products {
		v, err := strconv.ParseFloat(p.ScoreSet.BaseScore, 32)
		if err != nil {
			continue
		}
		if v3score < v {
			v3score = v
			v3Vector = p.ScoreSet.Vector
		}
	}

	var v3Severity string
	for _, p := range cve.Products {
		v3Severity = p.Severity
	}

	option := map[string]string{}
	if 0 < len(cve.ExploitStatus) {
		// TODO: CVE-2020-0739
		// "exploit_status": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely;Older Software Release:Exploitation Less Likely;DOS:N/A",
		option["exploit"] = cve.ExploitStatus
	}

	mitigations := []models.Mitigation{}
	if cve.Mitigation != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Mitigation,
			URL:            cve.URL,
		})
	}
	if cve.Workaround != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Workaround,
			URL:            cve.URL,
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
		Published:     cve.PublishDate,
		LastModified:  cve.LastUpdateDate,
		SourceLink:    cve.URL,
		Optional:      option,
	}, mitigations
}
