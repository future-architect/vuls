//go:build !scanner

package oval

import (
	"fmt"
	"maps"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// SUSE is the struct of SUSE Linux
type SUSE struct {
	Base
}

// NewSUSE creates OVAL client for SUSE
func NewSUSE(driver ovaldb.DB, baseURL, family string) SUSE {
	// TODO implement other family
	return SUSE{
		Base{
			driver:  driver,
			baseURL: baseURL,
			family:  family,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o SUSE) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
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
	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		if conts, ok := vuln.CveContents[models.SUSE]; ok {
			for i, cont := range conts {
				cont.SourceLink = fmt.Sprintf("https://www.suse.com/security/cve/%s.html", cont.CveID)
				vuln.CveContents[models.SUSE][i] = cont
			}
		}
	}
	return len(relatedDefs.entries), nil
}

func (o SUSE) update(r *models.ScanResult, defpacks defPacks) {
	ovalContent := o.convertToModel(&defpacks.def)
	if ovalContent == nil {
		return
	}
	ovalContent.Type = models.NewCveContentType(o.family)
	vinfo, ok := r.ScannedCves[ovalContent.CveID]
	if !ok {
		logging.Log.Debugf("%s is newly detected by OVAL", ovalContent.CveID)
		vinfo = models.VulnInfo{
			CveID:       ovalContent.CveID,
			Confidences: models.Confidences{models.OvalMatch},
			CveContents: models.NewCveContents(*ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			logging.Log.Debugf("%s OVAL will be overwritten", ovalContent.CveID)
		} else {
			logging.Log.Debugf("%s is also detected by OVAL", ovalContent.CveID)
			cveContents = models.CveContents{}
		}
		vinfo.Confidences.AppendIfMissing(models.OvalMatch)
		cveContents[ctype] = []models.CveContent{*ovalContent}
		vinfo.CveContents = cveContents
	}

	// uniq(vinfo.AffectedPackages[].Name + defPacks.binpkgFixstat(map[string(=package name)]fixStat{}))
	collectBinpkgFixstat := defPacks{
		binpkgFixstat: map[string]fixStat{},
	}
	maps.Copy(collectBinpkgFixstat.binpkgFixstat, defpacks.binpkgFixstat)

	for _, pack := range vinfo.AffectedPackages {
		collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
			notFixedYet: pack.NotFixedYet,
			fixedIn:     pack.FixedIn,
		}
	}
	vinfo.AffectedPackages = collectBinpkgFixstat.toPackStatuses()
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[ovalContent.CveID] = vinfo
}

func (o SUSE) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	refs := []models.Reference{}
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	var c *models.CveContent
	for _, cve := range def.Advisory.Cves {
		switch {
		case strings.Contains(cve.Href, "www.suse.com"):
			score3, vec3 := parseCvss3(cve.Cvss3)
			return &models.CveContent{
				Title:         def.Title,
				Summary:       def.Description,
				CveID:         strings.TrimSuffix(cve.CveID, " at SUSE"),
				Cvss3Score:    score3,
				Cvss3Vector:   vec3,
				Cvss3Severity: cve.Impact,
				References:    refs,
			}
		default:
			c = &models.CveContent{
				Title:      def.Title,
				Summary:    def.Description,
				CveID:      strings.TrimSuffix(cve.CveID, " at NVD"),
				References: refs,
			}
		}
	}
	return c
}
