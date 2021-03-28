// +build !scanner

package gost

import (
	"encoding/json"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
	"golang.org/x/xerrors"
)

// Debian is Gost client for Debian GNU/Linux
type Debian struct {
	Base
}

type packCves struct {
	packName  string
	isSrcPack bool
	cves      []models.CveContent
	fixes     models.PackageFixStatuses
}

func (deb Debian) supported(major string) bool {
	_, ok := map[string]string{
		"8":  "jessie",
		"9":  "stretch",
		"10": "buster",
	}[major]
	return ok
}

// DetectCVEs fills cve information that has in Gost
func (deb Debian) DetectCVEs(driver db.DB, r *models.ScanResult, _ bool) (nCVEs int, err error) {
	if !deb.supported(major(r.Release)) {
		// only logging
		logging.Log.Warnf("Debian %s is not supported yet", r.Release)
		return 0, nil
	}

	// Add linux and set the version of running kernel to search OVAL.
	if r.Container.ContainerID == "" {
		newVer := ""
		if p, ok := r.Packages["linux-image-"+r.RunningKernel.Release]; ok {
			newVer = p.NewVersion
		}
		r.Packages["linux"] = models.Package{
			Name:       "linux",
			Version:    r.RunningKernel.Version,
			NewVersion: newVer,
		}
	}

	// Debian Security Tracker does not support Package for Raspbian, so skip it.
	if r.Family == constant.Raspbian {
		r = r.RemoveRaspbianPackFromResult()
	}

	nFixedCVEs, err := deb.detectCVEsWithFixState(driver, r, "resolved")
	if err != nil {
		return 0, err
	}

	nUnfixedCVEs, err := deb.detectCVEsWithFixState(driver, r, "open")
	if err != nil {
		return 0, err
	}

	return (nFixedCVEs + nUnfixedCVEs), nil
}

func (deb Debian) detectCVEsWithFixState(driver db.DB, r *models.ScanResult, fixStatus string) (nCVEs int, err error) {
	if fixStatus != "resolved" && fixStatus != "open" {
		return 0, xerrors.Errorf(`Failed to detectCVEsWithFixState. fixStatus is not allowed except "open" and "resolved"(actual: fixStatus -> %s).`, fixStatus)
	}

	packCvesList := []packCves{}
	if config.Conf.Gost.IsFetchViaHTTP() {
		url, _ := util.URLPathJoin(config.Conf.Gost.URL, "debian", major(r.Release), "pkgs")
		s := func(s string) string {
			if s == "resolved" {
				return "fixed-cves"
			}
			return "unfixed-cves"
		}(fixStatus)

		responses, err := getCvesWithFixStateViaHTTP(r, url, s)
		if err != nil {
			return 0, err
		}

		for _, res := range responses {
			debCves := map[string]gostmodels.DebianCVE{}
			if err := json.Unmarshal([]byte(res.json), &debCves); err != nil {
				return 0, err
			}
			cves := []models.CveContent{}
			fixes := []models.PackageFixStatus{}
			for _, debcve := range debCves {
				cves = append(cves, *deb.ConvertToModel(&debcve))
				fixes = append(fixes, checkPackageFixStatus(&debcve)...)
			}
			packCvesList = append(packCvesList, packCves{
				packName:  res.request.packName,
				isSrcPack: res.request.isSrcPack,
				cves:      cves,
				fixes:     fixes,
			})
		}
	} else {
		if driver == nil {
			return 0, nil
		}
		for _, pack := range r.Packages {
			cves, fixes := deb.getCvesDebianWithfixStatus(driver, fixStatus, major(r.Release), pack.Name)
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: false,
				cves:      cves,
				fixes:     fixes,
			})
		}

		// SrcPack
		for _, pack := range r.SrcPackages {
			cves, fixes := deb.getCvesDebianWithfixStatus(driver, fixStatus, major(r.Release), pack.Name)
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: true,
				cves:      cves,
				fixes:     fixes,
			})
		}
	}

	delete(r.Packages, "linux")

	for _, p := range packCvesList {
		for _, cve := range p.cves {
			v, ok := r.ScannedCves[cve.CveID]
			if ok {
				if v.CveContents == nil {
					v.CveContents = models.NewCveContents(cve)
				} else {
					v.CveContents[models.DebianSecurityTracker] = cve
					v.Confidences = models.Confidences{models.DebianSecurityTrackerMatch}
				}
			} else {
				v = models.VulnInfo{
					CveID:       cve.CveID,
					CveContents: models.NewCveContents(cve),
					Confidences: models.Confidences{models.DebianSecurityTrackerMatch},
				}
				nCVEs++
			}

			for _, f := range p.fixes {
				if f.Name == "linux" {
					f.Name = "linux-image-" + r.RunningKernel.Release
				}
				v.AffectedPackages = v.AffectedPackages.Store(f)
			}
			r.ScannedCves[cve.CveID] = v
		}
	}

	return nCVEs, nil
}

func (deb Debian) getCvesDebianWithfixStatus(driver db.DB, fixStatus, release, pkgName string) (cves []models.CveContent, fixes []models.PackageFixStatus) {
	cveDebs := func(s string) map[string]gostmodels.DebianCVE {
		if s == "resolved" {
			return driver.GetFixedCvesDebian(release, pkgName)
		}
		return driver.GetUnfixedCvesDebian(release, pkgName)
	}(fixStatus)

	for _, cveDeb := range cveDebs {
		cves = append(cves, *deb.ConvertToModel(&cveDeb))
		fixes = append(fixes, checkPackageFixStatus(&cveDeb)...)
	}

	return
}

// ConvertToModel converts gost model to vuls model
func (deb Debian) ConvertToModel(cve *gostmodels.DebianCVE) *models.CveContent {
	severity := ""
	for _, p := range cve.Package {
		for _, r := range p.Release {
			severity = r.Urgency
			break
		}
	}
	return &models.CveContent{
		Type:          models.DebianSecurityTracker,
		CveID:         cve.CveID,
		Summary:       cve.Description,
		Cvss2Severity: severity,
		Cvss3Severity: severity,
		SourceLink:    "https://security-tracker.debian.org/tracker/" + cve.CveID,
		Optional: map[string]string{
			"attack range": cve.Scope,
		},
	}
}

//
func checkPackageFixStatus(cve *gostmodels.DebianCVE) []models.PackageFixStatus {
	fixes := []models.PackageFixStatus{}
	for _, p := range cve.Package {
		for _, r := range p.Release {
			f := func(name string, rel gostmodels.DebianRelease) models.PackageFixStatus {
				if r.Status == "open" {
					return models.PackageFixStatus{Name: name, NotFixedYet: true, FixState: rel.Status}
				}
				return models.PackageFixStatus{Name: name, FixedIn: r.FixedVersion}
			}(p.PackageName, r)
			fixes = append(fixes, f)

			break
		}
	}

	return fixes
}
