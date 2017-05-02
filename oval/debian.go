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

// Debian is the interface for Debian OVAL
type Debian struct{}

// NewDebian creates OVAL client for Debian
func NewDebian() Debian {
	return Debian{}
}

// FillCveInfoFromOvalDB returns scan result after updating CVE info by OVAL
func (o Debian) FillCveInfoFromOvalDB(r *models.ScanResult) (*models.ScanResult, error) {
	util.Log.Debugf("open oval-dictionary db (%s)", config.Conf.OvalDBType)
	ovalconf.Conf.DBType = config.Conf.OvalDBType
	ovalconf.Conf.DBPath = config.Conf.OvalDBPath

	if err := db.OpenDB(); err != nil {
		return nil, fmt.Errorf("Failed to open OVAL DB. err: %s", err)
	}

	var d db.OvalDB
	switch r.Family {
	case "debian":
		d = db.NewDebian()
	case "ubuntu":
		d = db.NewUbuntu()
	}
	for _, pack := range r.Packages {
		definitions, err := d.GetByPackName(r.Release, pack.Name)
		if err != nil {
			return nil, fmt.Errorf("Failed to get Debian OVAL info by package name: %v", err)
		}
		for _, definition := range definitions {
			current, _ := ver.NewVersion(pack.Version)
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

func (o Debian) fillOvalInfo(r *models.ScanResult, definition *ovalmodels.Definition) *models.ScanResult {
	// Update ScannedCves by OVAL info
	found := false
	updatedCves := []models.VulnInfo{}

	// Update scanned confidence to ovalmatch
	for _, scanned := range r.ScannedCves {
		if scanned.CveID == definition.Debian.CveID {
			found = true
			if scanned.Confidence.Score < models.OvalMatch.Score {
				scanned.Confidence = models.OvalMatch
			}
		}
		updatedCves = append(updatedCves, scanned)
	}

	vuln := models.VulnInfo{
		CveID:      definition.Debian.CveID,
		Confidence: models.OvalMatch,
		Packages:   getPackageInfoList(r, definition),
	}

	if !found {
		util.Log.Debugf("%s is newly detected by OVAL", vuln.CveID)
		updatedCves = append(updatedCves, vuln)
	}
	r.ScannedCves = updatedCves

	// Update KnownCves by OVAL info
	ovalContent := *o.convertToModel(definition)
	ovalContent.Type = models.CveContentType(r.Family)
	cInfo, ok := r.KnownCves.Get(definition.Debian.CveID)
	if !ok {
		cInfo.VulnInfo = vuln
		cInfo.CveContents = []models.CveContent{ovalContent}
	}
	if !cInfo.Update(ovalContent) {
		cInfo.Insert(ovalContent)
	}
	if cInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
		cInfo.Confidence = models.OvalMatch
	}
	r.KnownCves.Upsert(cInfo)

	// Update UnknownCves by OVAL info
	cInfo, ok = r.UnknownCves.Get(definition.Debian.CveID)
	if ok {
		r.UnknownCves.Delete(definition.Debian.CveID)

		// Insert new CveInfo
		if !cInfo.Update(ovalContent) {
			cInfo.Insert(ovalContent)
		}
		if cInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
			cInfo.Confidence = models.OvalMatch
		}
		r.KnownCves.Upsert(cInfo)
	}

	return r
}

func (o Debian) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	var refs []models.Reference
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}
	return &models.CveContent{
		CveID:      def.Debian.CveID,
		Title:      def.Title,
		Summary:    def.Description,
		References: refs,
	}
}
