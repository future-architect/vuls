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

// Redhat is the interface for Redhat OVAL
type Redhat struct{}

// NewRedhat creates OVAL client for Redhat
func NewRedhat() Redhat {
	return Redhat{}
}

// FillCveInfoFromOvalDB returns scan result after updating CVE info by OVAL
func (o Redhat) FillCveInfoFromOvalDB(r models.ScanResult) (*models.ScanResult, error) {
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
					r = o.fillOvalInfo(r, definition)
				}
			}
		}
	}
	return &r, nil
}

func (o Redhat) fillOvalInfo(r models.ScanResult, definition ovalmodels.Definition) models.ScanResult {
	found := make(map[string]bool)
	vulnInfos := make(map[string]models.VulnInfo)
	packageInfoList := getPackageInfoList(r, definition)
	for _, cve := range definition.Advisory.Cves {
		found[cve.CveID] = false
		vulnInfos[cve.CveID] = models.VulnInfo{
			CveID:      cve.CveID,
			Confidence: models.OvalMatch,
			Packages:   packageInfoList,
		}
	}

	// Update ScannedCves by OVAL info
	cves := []models.VulnInfo{}
	for _, scannedCve := range r.ScannedCves {
		for _, c := range definition.Advisory.Cves {
			if scannedCve.CveID == c.CveID {
				found[c.CveID] = true
				if scannedCve.Confidence.Score < models.OvalMatch.Score {
					scannedCve.Confidence = models.OvalMatch
				}
				break
			}
		}
		cves = append(cves, scannedCve)
	}

	for cveID, found := range found {
		if !found {
			cves = append(cves, vulnInfos[cveID])
			util.Log.Debugf("%s is newly detected by OVAL", cveID)
		}
	}
	r.ScannedCves = cves

	// Update KnownCves by OVAL info
	for _, c := range definition.Advisory.Cves {
		cveInfo, ok := r.KnownCves.Get(c.CveID)
		if !ok {
			cveInfo.CveDetail = cve.CveDetail{
				CveID: c.CveID,
			}
			cveInfo.VulnInfo = vulnInfos[c.CveID]
		}
		cveInfo.OvalDetail = definition
		if cveInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
			cveInfo.Confidence = models.OvalMatch
		}
		r.KnownCves.Upsert(cveInfo)
	}

	// Update UnknownCves by OVAL info
	for _, c := range definition.Advisory.Cves {
		cveInfo, ok := r.UnknownCves.Get(c.CveID)
		if ok {
			cveInfo.OvalDetail = definition
			if cveInfo.VulnInfo.Confidence.Score < models.OvalMatch.Score {
				cveInfo.Confidence = models.OvalMatch
			}
			r.UnknownCves.Delete(c.CveID)
			r.KnownCves.Upsert(cveInfo)
		}
	}

	return r
}
