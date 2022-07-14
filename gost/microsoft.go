//go:build !scanner
// +build !scanner

package gost

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/logging"
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
	osName, ok := r.Optional["OSName"].(string)
	if !ok {
		logging.Log.Warnf("This Windows has wrong type option(OSName). UUID: %s", r.ServerUUID)
	}

	var products []string
	if _, ok := r.Optional["InstalledProducts"]; ok {
		switch ps := r.Optional["InstalledProducts"].(type) {
		case []interface{}:
			for _, p := range ps {
				pname, ok := p.(string)
				if !ok {
					logging.Log.Warnf("skip products: %v", p)
					continue
				}
				products = append(products, pname)
			}
		case []string:
			for _, p := range ps {
				products = append(products, p)
			}
		case nil:
			logging.Log.Warnf("This Windows has no option(InstalledProducts). UUID: %s", r.ServerUUID)
		}
	}

	applied, unapplied := map[string]struct{}{}, map[string]struct{}{}
	if _, ok := r.Optional["KBID"]; ok {
		switch kbIDs := r.Optional["KBID"].(type) {
		case []interface{}:
			for _, kbID := range kbIDs {
				s, ok := kbID.(string)
				if !ok {
					logging.Log.Warnf("skip KBID: %v", kbID)
					continue
				}
				unapplied[strings.TrimPrefix(s, "KB")] = struct{}{}
			}
		case []string:
			for _, kbID := range kbIDs {
				unapplied[strings.TrimPrefix(kbID, "KB")] = struct{}{}
			}
		case nil:
			logging.Log.Warnf("This Windows has no option(KBID). UUID: %s", r.ServerUUID)
		}

		for _, pkg := range r.Packages {
			matches := kbIDPattern.FindAllStringSubmatch(pkg.Name, -1)
			for _, match := range matches {
				applied[match[1]] = struct{}{}
			}
		}
	} else {
		switch kbIDs := r.Optional["AppliedKBID"].(type) {
		case []interface{}:
			for _, kbID := range kbIDs {
				s, ok := kbID.(string)
				if !ok {
					logging.Log.Warnf("skip KBID: %v", kbID)
					continue
				}
				applied[strings.TrimPrefix(s, "KB")] = struct{}{}
			}
		case []string:
			for _, kbID := range kbIDs {
				applied[strings.TrimPrefix(kbID, "KB")] = struct{}{}
			}
		case nil:
			logging.Log.Warnf("This Windows has no option(AppliedKBID). UUID: %s", r.ServerUUID)
		}

		switch kbIDs := r.Optional["UnappliedKBID"].(type) {
		case []interface{}:
			for _, kbID := range kbIDs {
				s, ok := kbID.(string)
				if !ok {
					logging.Log.Warnf("skip KBID: %v", kbID)
					continue
				}
				unapplied[strings.TrimPrefix(s, "KB")] = struct{}{}
			}
		case []string:
			for _, kbID := range kbIDs {
				unapplied[strings.TrimPrefix(kbID, "KB")] = struct{}{}
			}
		case nil:
			logging.Log.Warnf("This Windows has no option(UnappliedKBID). UUID: %s", r.ServerUUID)
		}
	}

	logging.Log.Debugf(`GetCvesByMicrosoftKBID query body {"osName": %s, "installedProducts": %q, "applied": %q, "unapplied: %q"}`, osName, products, maps.Keys(applied), maps.Keys(unapplied))
	cves, err := ms.driver.GetCvesByMicrosoftKBID(osName, products, maps.Keys(applied), maps.Keys(unapplied))
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect CVEs. err: %w", err)
	}

	for cveID, cve := range cves {
		cveCont, mitigations := ms.ConvertToModel(&cve)
		uniqKB := map[string]struct{}{}
		for _, p := range cve.Products {
			for _, kb := range p.KBs {
				if _, err := strconv.Atoi(kb.Article); err == nil {
					uniqKB[fmt.Sprintf("KB%s", kb.Article)] = struct{}{}
				} else {
					uniqKB[kb.Article] = struct{}{}
				}
			}
		}
		advisories := []models.DistroAdvisory{}
		for kb := range uniqKB {
			advisories = append(advisories, models.DistroAdvisory{
				AdvisoryID:  kb,
				Description: "Microsoft Knowledge Base",
			})
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
		v, err := strconv.ParseFloat(p.ScoreSet.BaseScore, 64)
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
