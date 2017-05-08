package oval

import (
	"fmt"
	"strconv"
	"strings"

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
func (o Redhat) FillCveInfoFromOvalDB(r *models.ScanResult) error {
	ovalconf.Conf.DBType = config.Conf.OvalDBType
	ovalconf.Conf.DBPath = config.Conf.OvalDBPath
	util.Log.Infof("open oval-dictionary db (%s): %s",
		config.Conf.OvalDBType, config.Conf.OvalDBPath)

	if err := db.OpenDB(); err != nil {
		return fmt.Errorf("Failed to open OVAL DB. err: %s", err)
	}

	d := db.NewRedHat()

	for _, pack := range r.Packages {
		definitions, err := d.GetByPackName(r.Release, pack.Name)
		if err != nil {
			return fmt.Errorf("Failed to get RedHat OVAL info by package name: %v", err)
		}
		for _, definition := range definitions {
			current, _ := ver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
			for _, p := range definition.AffectedPacks {
				if pack.Name != p.Name {
					continue
				}
				affected, _ := ver.NewVersion(p.Version)
				if current.LessThan(affected) {
					o.fillOvalInfo(r, &definition)
				}
			}
		}
	}
	return nil
}

func (o Redhat) fillOvalInfo(r *models.ScanResult, definition *ovalmodels.Definition) {
	for _, cve := range definition.Advisory.Cves {
		ovalContent := *o.convertToModel(cve.CveID, definition)
		vinfo, ok := r.ScannedCves.Get(cve.CveID)
		if !ok {
			util.Log.Infof("%s is newly detected by OVAL", cve.CveID)
			vinfo = models.VulnInfo{
				CveID:        cve.CveID,
				Confidence:   models.OvalMatch,
				PackageNames: getPackages(r, definition),
				CveContents:  models.NewCveContents(ovalContent),
			}
		} else {
			if _, ok := vinfo.CveContents.Get(models.RedHat); !ok {
				util.Log.Infof("%s is also detected by OVAL", cve.CveID)
			} else {
				util.Log.Infof("%s will be updated by OVAL", cve.CveID)
			}
			if vinfo.Confidence.Score < models.OvalMatch.Score {
				vinfo.Confidence = models.OvalMatch
			}
			vinfo.CveContents.Upsert(ovalContent)
		}
		r.ScannedCves.Upsert(vinfo)
	}
}

func (o Redhat) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}
		var refs []models.Reference
		for _, r := range def.References {
			refs = append(refs, models.Reference{
				Link:   r.RefURL,
				Source: r.Source,
				RefID:  r.RefID,
			})
		}

		score2, vec2 := o.parseCvss2(cve.Cvss2)
		score3, vec3 := o.parseCvss3(cve.Cvss3)

		return &models.CveContent{
			Type:         models.RedHat,
			CveID:        cve.CveID,
			Title:        def.Title,
			Summary:      def.Description,
			Severity:     def.Advisory.Severity,
			Cvss2Score:   score2,
			Cvss2Vector:  vec2,
			Cvss3Score:   score3,
			Cvss3Vector:  vec3,
			References:   refs,
			CweID:        cve.Cwe,
			Published:    def.Advisory.Issued,
			LastModified: def.Advisory.Updated,
		}
	}
	return nil
}

// ParseCvss2 divide CVSSv2 string into score and vector
// 5/AV:N/AC:L/Au:N/C:N/I:N/A:P
func (o Redhat) parseCvss2(scoreVector string) (score float64, vector string) {
	var err error
	ss := strings.Split(scoreVector, "/")
	if 1 < len(ss) {
		if score, err = strconv.ParseFloat(ss[0], 64); err != nil {
			return 0, ""
		}
		return score, strings.Join(ss[1:len(ss)], "/")
	}
	return 0, ""
}

// ParseCvss3 divide CVSSv3 string into score and vector
// 5.6/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L
func (o Redhat) parseCvss3(scoreVector string) (score float64, vector string) {
	var err error
	ss := strings.Split(scoreVector, "/CVSS:3.0/")
	if 1 < len(ss) {
		if score, err = strconv.ParseFloat(ss[0], 64); err != nil {
			return 0, ""
		}
		return score, strings.Join(ss[1:len(ss)], "/")
	}
	return 0, ""
}
