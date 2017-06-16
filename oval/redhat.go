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

// RedHatBase is the base struct for RedHat and CentOS
type RedHatBase struct{ Base }

// FillWithOval returns scan result after updating CVE info by OVAL
func (o RedHatBase) FillWithOval(r *models.ScanResult) error {
	if o.isFetchViaHTTP() {
		defs, err := getDefsByPackNameViaHTTP(r)
		if err != nil {
			return err
		}
		for _, def := range defs {
			o.update(r, &def)
		}
	} else {
		if err := o.fillFromOvalDB(r); err != nil {
			return err
		}
	}

	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.RedHat]; ok {
			cont.SourceLink = "https://access.redhat.com/security/cve/" + cont.CveID
		}
	}
	return nil
}

// fillFromOvalDB returns scan result after updating CVE info by OVAL
func (o RedHatBase) fillFromOvalDB(r *models.ScanResult) error {
	defs, err := o.getDefsByPackNameFromOvalDB(r.Release, r.Packages)
	if err != nil {
		return err
	}
	for _, def := range defs {
		o.update(r, &def)
	}
	return nil
}

func (o RedHatBase) getDefsByPackNameFromOvalDB(osRelease string,
	packs models.Packages) (relatedDefs []ovalmodels.Definition, err error) {

	ovalconf.Conf.DBType = config.Conf.OvalDBType
	ovalconf.Conf.DBPath = config.Conf.OvalDBPath
	util.Log.Infof("open oval-dictionary db (%s): %s",
		config.Conf.OvalDBType, config.Conf.OvalDBPath)

	d := db.NewRedHat()
	defer d.Close()
	for _, pack := range packs {
		definitions, err := d.GetByPackName(osRelease, pack.Name)
		if err != nil {
			return nil, fmt.Errorf("Failed to get RedHat OVAL info by package name: %v", err)
		}
		for _, def := range definitions {
			current, _ := ver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
			for _, p := range def.AffectedPacks {
				affected, _ := ver.NewVersion(p.Version)
				if pack.Name != p.Name || !current.LessThan(affected) {
					continue
				}
				relatedDefs = append(relatedDefs, def)
			}
		}
	}
	return
}

func (o RedHatBase) update(r *models.ScanResult, definition *ovalmodels.Definition) {
	for _, cve := range definition.Advisory.Cves {
		ovalContent := *o.convertToModel(cve.CveID, definition)
		vinfo, ok := r.ScannedCves[cve.CveID]
		if !ok {
			util.Log.Infof("%s is newly detected by OVAL", cve.CveID)
			vinfo = models.VulnInfo{
				CveID:        cve.CveID,
				Confidence:   models.OvalMatch,
				PackageNames: getPackages(r, definition),
				CveContents:  models.NewCveContents(ovalContent),
			}
		} else {
			cveContents := vinfo.CveContents
			if _, ok := vinfo.CveContents[models.RedHat]; ok {
				util.Log.Infof("%s will be updated by OVAL", cve.CveID)
			} else {
				util.Log.Infof("%s also detected by OVAL", cve.CveID)
				cveContents = models.CveContents{}
			}

			if vinfo.Confidence.Score < models.OvalMatch.Score {
				vinfo.Confidence = models.OvalMatch
			}
			cveContents[models.RedHat] = ovalContent
			vinfo.CveContents = cveContents
		}
		r.ScannedCves[cve.CveID] = vinfo
	}
}

func (o RedHatBase) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
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
			SourceLink:   "https://access.redhat.com/security/cve/" + cve.CveID,
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
func (o RedHatBase) parseCvss2(scoreVector string) (score float64, vector string) {
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
func (o RedHatBase) parseCvss3(scoreVector string) (score float64, vector string) {
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

// RedHat is the interface for RedhatBase OVAL
type RedHat struct {
	RedHatBase
}

// NewRedhat creates OVAL client for Redhat
func NewRedhat() RedHat {
	return RedHat{}
}

// CentOS is the interface for CentOS OVAL
type CentOS struct {
	RedHatBase
}

// NewCentOS creates OVAL client for CentOS
func NewCentOS() CentOS {
	return CentOS{}
}
