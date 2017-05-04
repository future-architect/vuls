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
	ovalContent := *o.convertToModel(definition)
	ovalContent.Type = models.CveContentType(r.Family)
	vinfo, ok := r.ScannedCves.Get(definition.Debian.CveID)
	if !ok {
		util.Log.Infof("%s is newly detected by OVAL",
			definition.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:       definition.Debian.CveID,
			Confidence:  models.OvalMatch,
			Packages:    getPackageInfoList(r, definition),
			CveContents: []models.CveContent{ovalContent},
		}
	} else {
		if _, ok := vinfo.CveContents.Get(models.CveContentType(r.Family)); !ok {
			util.Log.Infof("%s is also detected by OVAL", definition.Debian.CveID)
		} else {
			util.Log.Infof("%s will be updated by OVAL", definition.Debian.CveID)
		}
		if vinfo.Confidence.Score < models.OvalMatch.Score {
			vinfo.Confidence = models.OvalMatch
		}
		vinfo.CveContents.Upsert(ovalContent)
	}
	r.ScannedCves.Upsert(vinfo)
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
		Severity:   def.Advisory.Severity,
		References: refs,
	}
}
