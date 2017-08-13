package oval

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ver "github.com/knqyf263/go-deb-version"
	db "github.com/kotakanbe/goval-dictionary/db"
	ovallog "github.com/kotakanbe/goval-dictionary/log"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
	family string
}

// fillFromOvalDB returns scan result after updating CVE info by OVAL
func (o DebianBase) fillFromOvalDB(r *models.ScanResult) error {
	defs, err := o.getDefsByPackNameFromOvalDB(r.Release, r.Packages)
	if err != nil {
		return err
	}
	for _, def := range defs {
		o.update(r, &def)
	}
	return nil
}

func (o DebianBase) getDefsByPackNameFromOvalDB(osRelease string,
	packs models.Packages) (relatedDefs []ovalmodels.Definition, err error) {

	ovallog.Initialize(config.Conf.LogDir)
	path := config.Conf.OvalDBURL
	if config.Conf.OvalDBType == "sqlite3" {
		path = config.Conf.OvalDBPath
	}
	util.Log.Debugf("Open oval-dictionary db (%s): %s", config.Conf.OvalDBType, path)

	var ovaldb db.DB
	if ovaldb, err = db.NewDB(
		o.family,
		config.Conf.OvalDBType,
		path,
		config.Conf.DebugSQL,
	); err != nil {
		return
	}
	defer ovaldb.CloseDB()

	for _, pack := range packs {
		definitions, err := ovaldb.GetByPackName(osRelease, pack.Name)
		if err != nil {
			return nil, fmt.Errorf("Failed to get %s OVAL info by package name: %v", o.family, err)
		}
		for _, def := range definitions {
			current, _ := ver.NewVersion(pack.Version)
			for _, p := range def.AffectedPacks {
				if pack.Name != p.Name {
					continue
				}
				affected, _ := ver.NewVersion(p.Version)
				if current.LessThan(affected) {
					relatedDefs = append(relatedDefs, def)
				}
			}
		}
	}
	return
}

func (o DebianBase) update(r *models.ScanResult, definition *ovalmodels.Definition) {
	ovalContent := *o.convertToModel(definition)
	ovalContent.Type = models.NewCveContentType(r.Family)
	vinfo, ok := r.ScannedCves[definition.Debian.CveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", definition.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:        definition.Debian.CveID,
			Confidence:   models.OvalMatch,
			PackageNames: getPackages(r, definition),
			CveContents:  models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(r.Family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			util.Log.Debugf("%s will be updated by OVAL", definition.Debian.CveID)
		} else {
			util.Log.Debugf("%s is also detected by OVAL", definition.Debian.CveID)
			cveContents = models.CveContents{}
		}
		if vinfo.Confidence.Score < models.OvalMatch.Score {
			vinfo.Confidence = models.OvalMatch
		}
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}
	r.ScannedCves[definition.Debian.CveID] = vinfo
}

func (o DebianBase) convertToModel(def *ovalmodels.Definition) *models.CveContent {
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

// Debian is the interface for Debian OVAL
type Debian struct {
	DebianBase
}

// NewDebian creates OVAL client for Debian
func NewDebian() Debian {
	return Debian{
		DebianBase{
			family: config.Debian,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Debian) FillWithOval(r *models.ScanResult) error {
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

	// TODO merge to VulnInfo.VendorLinks
	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.Debian]; ok {
			cont.SourceLink = "https://security-tracker.debian.org/tracker/" + cont.CveID
			vuln.CveContents[models.Debian] = cont
		}
	}
	return nil
}

// Ubuntu is the interface for Debian OVAL
type Ubuntu struct {
	DebianBase
}

// NewUbuntu creates OVAL client for Debian
func NewUbuntu() Ubuntu {
	return Ubuntu{
		DebianBase{
			family: config.Ubuntu,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Ubuntu) FillWithOval(r *models.ScanResult) error {
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

	// TODO merge to VulnInfo.VendorLinks
	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.Ubuntu]; ok {
			cont.SourceLink = "http://people.ubuntu.com/~ubuntu-security/cve/" + cont.CveID
			vuln.CveContents[models.Ubuntu] = cont
		}
	}
	return nil
}
