//go:build !scanner

package oval

import (
	"fmt"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// RedHatBase is the base struct for RedHat, CentOS, Alma, Rocky and Fedora
type RedHatBase struct {
	Base
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o RedHatBase) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.driver == nil {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.baseURL); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions via HTTP. err: %w", err)
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(r, o.driver); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions from DB. err: %w", err)
		}
	}

	relatedDefs.Sort()
	for _, defPacks := range relatedDefs.entries {
		nCVEs += o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		switch models.NewCveContentType(o.family) {
		case models.Amazon:
			for _, d := range vuln.DistroAdvisories {
				if conts, ok := vuln.CveContents[models.Amazon]; ok {
					for i, cont := range conts {
						switch {
						case strings.HasPrefix(d.AdvisoryID, "ALAS-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/%s.html", d.AdvisoryID)
						case strings.HasPrefix(d.AdvisoryID, "ALAS2-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2", "ALAS"))
						case strings.HasPrefix(d.AdvisoryID, "ALAS2022-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2022/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2022", "ALAS"))
						case strings.HasPrefix(d.AdvisoryID, "ALAS2023-"):
							cont.SourceLink = fmt.Sprintf("https://alas.aws.amazon.com/AL2023/%s.html", strings.ReplaceAll(d.AdvisoryID, "ALAS2023", "ALAS"))
						}
						vuln.CveContents[models.Amazon][i] = cont
					}
				}
			}
		}
	}

	return nCVEs, nil
}

func (o RedHatBase) update(r *models.ScanResult, defpacks defPacks) (nCVEs int) {
	for _, cve := range defpacks.def.Advisory.Cves {
		ovalContent := o.convertToModel(cve.CveID, &defpacks.def)
		if ovalContent == nil {
			continue
		}
		vinfo, ok := r.ScannedCves[cve.CveID]
		if !ok {
			logging.Log.Debugf("%s is newly detected by OVAL: DefID: %s", cve.CveID, defpacks.def.DefinitionID)
			vinfo = models.VulnInfo{
				CveID:       cve.CveID,
				Confidences: models.Confidences{models.OvalMatch},
				CveContents: models.NewCveContents(*ovalContent),
			}
			nCVEs++
		} else {
			cveContents := vinfo.CveContents
			if v, ok := vinfo.CveContents[ovalContent.Type]; ok {
				for _, vv := range v {
					if vv.LastModified.After(ovalContent.LastModified) {
						logging.Log.Debugf("%s ignored. DefID: %s ", cve.CveID, defpacks.def.DefinitionID)
					} else {
						logging.Log.Debugf("%s OVAL will be overwritten. DefID: %s", cve.CveID, defpacks.def.DefinitionID)
					}
				}
			} else {
				logging.Log.Debugf("%s also detected by OVAL. DefID: %s", cve.CveID, defpacks.def.DefinitionID)
				cveContents = models.CveContents{}
			}

			vinfo.Confidences.AppendIfMissing(models.OvalMatch)
			cveContents[ovalContent.Type] = []models.CveContent{*ovalContent}
			vinfo.CveContents = cveContents
		}

		if da := o.convertToDistroAdvisory(&defpacks.def); da != nil {
			vinfo.DistroAdvisories.AppendIfMissing(da)
		}

		// uniq(vinfo.AffectedPackages[].Name + defPacks.binpkgFixstat(map[string(=package name)]fixStat{}))
		collectBinpkgFixstat := defPacks{
			binpkgFixstat: map[string]fixStat{},
		}
		for packName, fixStatus := range defpacks.binpkgFixstat {
			collectBinpkgFixstat.binpkgFixstat[packName] = fixStatus
		}

		for _, pack := range vinfo.AffectedPackages {
			if stat, ok := collectBinpkgFixstat.binpkgFixstat[pack.Name]; !ok {
				collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: pack.NotFixedYet,
					fixState:    pack.FixState,
					fixedIn:     pack.FixedIn,
				}
			} else if stat.notFixedYet {
				collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
					notFixedYet: true,
					fixState:    pack.FixState,
					fixedIn:     pack.FixedIn,
				}
			}
		}
		vinfo.AffectedPackages = collectBinpkgFixstat.toPackStatuses()
		vinfo.AffectedPackages.Sort()
		r.ScannedCves[cve.CveID] = vinfo
	}
	return
}

func (o RedHatBase) convertToDistroAdvisory(def *ovalmodels.Definition) *models.DistroAdvisory {
	switch o.family {
	case constant.Amazon:
		if !strings.HasPrefix(def.Title, "ALAS") {
			return nil
		}
		return &models.DistroAdvisory{
			AdvisoryID:  def.Title,
			Severity:    def.Advisory.Severity,
			Issued:      def.Advisory.Issued,
			Updated:     def.Advisory.Updated,
			Description: def.Description,
		}
	default:
		return nil
	}
}

func (o RedHatBase) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
	refs := make([]models.Reference, 0, len(def.References))
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}

		score2, vec2 := parseCvss2(cve.Cvss2)
		score3, vec3 := parseCvss3(cve.Cvss3)

		sev2, sev3, severity := "", "", def.Advisory.Severity
		if cve.Impact != "" {
			severity = cve.Impact
		}
		if severity != "None" {
			sev3 = severity
			if score2 != 0 {
				sev2 = severity
			}
		}

		// CWE-ID in RedHat OVAL may have multiple cweIDs separated by space
		cwes := strings.Fields(cve.Cwe)

		return &models.CveContent{
			Type:          models.NewCveContentType(o.family),
			CveID:         cve.CveID,
			Title:         def.Title,
			Summary:       def.Description,
			Cvss2Score:    score2,
			Cvss2Vector:   vec2,
			Cvss2Severity: sev2,
			Cvss3Score:    score3,
			Cvss3Vector:   vec3,
			Cvss3Severity: sev3,
			References:    refs,
			CweIDs:        cwes,
			Published:     def.Advisory.Issued,
			LastModified:  def.Advisory.Updated,
		}
	}
	return nil
}

// Amazon is the interface for RedhatBase OVAL
type Amazon struct {
	// Base
	RedHatBase
}

// NewAmazon creates OVAL client for Amazon Linux
func NewAmazon(driver ovaldb.DB, baseURL string) Amazon {
	return Amazon{
		RedHatBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Amazon,
			},
		},
	}
}
