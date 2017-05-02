package oval

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ver "github.com/knqyf263/go-deb-version"
	ovalconf "github.com/kotakanbe/goval-dictionary/config"
	db "github.com/kotakanbe/goval-dictionary/db"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// Redhat is the interface for Redhat OVAL
type Redhat struct{}

// NewRedhat creates OVAL client for Redhat
func NewRedhat() Redhat {
	return Redhat{}
}

// FillCveInfoFromOvalDB returns scan result after updating CVE info by OVAL
func (o Redhat) FillCveInfoFromOvalDB(r *models.ScanResult) (*models.ScanResult, error) {
	util.Log.Debugf("open oval-dictionary db (%s)", config.Conf.OvalDBType)

	ovalconf.Conf.DBType = config.Conf.OvalDBType
	ovalconf.Conf.DBPath = config.Conf.OvalDBPath

	if err := db.OpenDB(); err != nil {
		return nil, fmt.Errorf("Failed to open OVAL DB. err: %s", err)
	}

	d := db.NewRedHat()

	for _, pack := range r.Packages {
		definitions, err := d.GetByPackName(r.Release, pack.Name)
		if err != nil {
			return nil, fmt.Errorf("Failed to get RedHat OVAL info by package name: %v", err)
		}
		for _, definition := range definitions {
			current, _ := ver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
			for _, p := range definition.AffectedPacks {
				if pack.Name != p.Name {
					continue
				}
				affected, _ := ver.NewVersion(p.Version)
				if current.LessThan(affected) {
					r = o.fillOvalInfo(r, &definition)
				}
			}
		}
	}
	return r, nil
}

func (o Redhat) fillOvalInfo(r *models.ScanResult, definition *ovalmodels.Definition) *models.ScanResult {
	cveIDSet := make(map[string]bool)
	cveID2VulnInfo := make(map[string]models.VulnInfo)
	for _, cve := range definition.Advisory.Cves {
		cveIDSet[cve.CveID] = false
		cveID2VulnInfo[cve.CveID] = models.VulnInfo{
			CveID:      cve.CveID,
			Confidence: models.OvalMatch,
			Packages:   getPackageInfoList(r, definition),
		}
	}

	// Update ScannedCves by OVAL info
	updatedCves := []models.VulnInfo{}
	for _, scanned := range r.ScannedCves {
		// Update scanned confidence to ovalmatch
		for _, c := range definition.Advisory.Cves {
			if scanned.CveID == c.CveID {
				cveIDSet[c.CveID] = true
				if scanned.Confidence.Score < models.OvalMatch.Score {
					scanned.Confidence = models.OvalMatch
				}
				break
			}
		}
		updatedCves = append(updatedCves, scanned)
	}

	for cveID, found := range cveIDSet {
		if !found {
			util.Log.Debugf("%s is newly detected by OVAL", cveID)
			updatedCves = append(updatedCves, cveID2VulnInfo[cveID])
		}
	}
	r.ScannedCves = updatedCves

	// Update KnownCves by OVAL info
	for _, c := range definition.Advisory.Cves {
		ovalContent := *o.convertToModel(c.CveID, definition)
		cInfo, ok := r.KnownCves.Get(c.CveID)
		if !ok {
			cInfo.VulnInfo = cveID2VulnInfo[c.CveID]
			cInfo.CveContents = []models.CveContent{ovalContent}
		}
		if !cInfo.Update(ovalContent) {
			cInfo.Insert(ovalContent)
		}
		if cInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
			cInfo.Confidence = models.OvalMatch
		}
		r.KnownCves.Upsert(cInfo)
	}

	// Update UnknownCves by OVAL info
	for _, c := range definition.Advisory.Cves {
		cInfo, ok := r.UnknownCves.Get(c.CveID)
		if ok {
			r.UnknownCves.Delete(c.CveID)

			// Insert new CveInfo
			ovalContent := *o.convertToModel(c.CveID, definition)
			if !cInfo.Update(ovalContent) {
				cInfo.Insert(ovalContent)
			}
			if cInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
				cInfo.Confidence = models.OvalMatch
			}
			r.KnownCves.Upsert(cInfo)
		}
	}

	return r
}

func (o Redhat) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}
		var refs []models.Reference
		//TODO RHSAのリンクを入れる
		for _, r := range def.References {
			refs = append(refs, models.Reference{
				Link:   r.RefURL,
				Source: r.Source,
				RefID:  r.RefID,
			})
		}

		//  util.ParseCvss2()

		return &models.CveContent{
			Type:     models.RedHat,
			CveID:    cve.CveID,
			Title:    def.Title,
			Summary:  def.Description,
			Severity: def.Advisory.Severity,
			//  V2Score:    v2Score,   // TODO divide into score and vector
			Cvss2Vector: cve.Cvss2, // TODO divide into score and vector
			Cvss3Vector: cve.Cvss3, // TODO divide into score and vector
			References:  refs,
			CweID:       cve.Cwe,
		}
	}
	return nil
}
