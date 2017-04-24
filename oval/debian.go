package oval

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ver "github.com/knqyf263/go-deb-version"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
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
func (o Debian) FillCveInfoFromOvalDB(r models.ScanResult) (*models.ScanResult, error) {
	util.Log.Debugf("open oval-dictionary db (%s)", config.Conf.OvalDBType)
	ovalconf.Conf.DBType = config.Conf.OvalDBType
	ovalconf.Conf.DBPath = config.Conf.OvalDBPath

	if err := db.OpenDB(); err != nil {
		return nil, fmt.Errorf("Failed to open OVAL DB. err: %s", err)
	}

	d := db.NewDebian()
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
					r = o.fillOvalInfo(r, definition)
				}
			}
		}
	}
	return &r, nil
}

func (o Debian) fillOvalInfo(r models.ScanResult, definition ovalmodels.Definition) models.ScanResult {
	// Update ScannedCves by OVAL info
	found := false
	cves := []models.VulnInfo{}
	for _, cve := range r.ScannedCves {
		if cve.CveID == definition.Debian.CveID {
			found = true
			if cve.Confidence.Score < models.OvalMatch.Score {
				cve.Confidence = models.OvalMatch
			}
		}
		cves = append(cves, cve)
	}

	packageInfoList := getPackageInfoList(r, definition)
	vuln := models.VulnInfo{
		CveID:      definition.Debian.CveID,
		Confidence: models.OvalMatch,
		Packages:   packageInfoList,
	}

	if !found {
		cves = append(cves, vuln)
	}
	r.ScannedCves = cves

	// Update KnownCves by OVAL info
	cveInfo, ok := r.KnownCves.Get(definition.Debian.CveID)
	if !ok {
		cveInfo.CveDetail = cve.CveDetail{
			CveID: definition.Debian.CveID,
		}
		cveInfo.VulnInfo = vuln
	}
	cveInfo.OvalDetail = definition
	if cveInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
		cveInfo.Confidence = models.OvalMatch
	}
	r.KnownCves.Upsert(cveInfo)

	// Update UnknownCves by OVAL info
	cveInfo, ok = r.UnknownCves.Get(definition.Debian.CveID)
	if ok {
		cveInfo.OvalDetail = definition
		if cveInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
			cveInfo.Confidence = models.OvalMatch
		}
		r.UnknownCves.Delete(definition.Debian.CveID)
		r.KnownCves.Upsert(cveInfo)
	}

	return r
}
