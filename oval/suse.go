//go:build !scanner
// +build !scanner

package oval

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// SUSE is the struct of SUSE Linux
type SUSE struct {
	Base
}

// NewSUSE creates OVAL client for SUSE
func NewSUSE(cnf config.VulnDictInterface, family string) SUSE {
	return SUSE{
		Base{
			family: family,
			Cnf:    cnf,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o SUSE) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.Cnf.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.Cnf.GetURL()); err != nil {
			return 0, err
		}
	} else {
		driver, err := newOvalDB(o.Cnf)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
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
	for packName, fixStatus := range defpacks.binpkgFixstat {
		collectBinpkgFixstat.binpkgFixstat[packName] = fixStatus
	}

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
	if len(def.Advisory.Cves) != 1 {
		logging.Log.Warnf("Unknown Oval format. Please register the issue as it needs to be investigated. https://github.com/vulsio/goval-dictionary/issues family: %s, defID: %s", o.family, def.DefinitionID)
		return nil
	}

	refs := []models.Reference{}
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}
	cve := def.Advisory.Cves[0]
	score3, vec3 := parseCvss3(cve.Cvss3)
	return &models.CveContent{
		Title:         def.Title,
		Summary:       def.Description,
		CveID:         cve.CveID,
		Cvss3Score:    score3,
		Cvss3Vector:   vec3,
		Cvss3Severity: cve.Impact,
		References:    refs,
	}
}
