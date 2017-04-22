package oval

import (
	"fmt"

	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
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
	ovalconf.Conf.DBType = "sqlite3"
	ovalconf.Conf.DBPath = "/Users/teppei/src/github.com/future-architect/vuls/oval.sqlite3"
	if err := db.OpenDB(); err != nil {
		fmt.Errorf("DB Open error")
		return nil, err
	}

	d := db.NewDebian()
	for _, pack := range r.Packages {
		// pp.Println(pack.Name)
		definitions, err := d.GetByPackName("8.2", pack.Name)
		if err != nil {
			fmt.Errorf("err")
			return nil, err
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

	// Update KnownCves by OVAL info
	known, unknown := models.CveInfos{}, models.CveInfos{}
	for _, k := range r.KnownCves {
		if k.CveID == definition.Debian.CveID {
			k.OvalDetail = definition
			if k.VulnInfo.Confidence.Score < models.OvalMatch.Score {
				k.VulnInfo.Confidence = models.OvalMatch
			}
		}
		known = append(known, k)
	}

	// Update UnknownCves by OVAL info
	for _, u := range r.UnknownCves {
		if u.CveID == definition.Debian.CveID {
			pp.Printf("found: %s\n", u.CveID)
			u.OvalDetail = definition
			if u.VulnInfo.Confidence.Score < models.OvalMatch.Score {
				u.VulnInfo.Confidence = models.OvalMatch
			}
			known = append(known, u)
		} else {
			unknown = append(unknown, u)
		}
	}

	// Update ScannedCves by OVAL info
	found := false
	cves := []models.VulnInfo{}
	for _, cve := range r.ScannedCves {
		if cve.CveID == definition.Debian.CveID &&
			cve.Confidence.Score < models.OvalMatch.Score {
			found = true
			cve.Confidence = models.OvalMatch
		}
		cves = append(cves, cve)
	}

	if !found {
		packageInfoList := getPackageInfoList(r, definition)
		vuln := models.VulnInfo{
			CveID:      definition.Debian.CveID,
			Confidence: models.OvalMatch,
			Packages:   packageInfoList,
		}
		cves = append(cves, vuln)

		known = append(known, models.CveInfo{
			CveDetail: cve.CveDetail{
				CveID: definition.Debian.CveID,
			},
			OvalDetail: definition,
			VulnInfo:   vuln,
		})
	}

	r.ScannedCves = cves
	r.KnownCves = known
	r.UnknownCves = unknown

	return r
}
