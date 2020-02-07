package gost

import (
	"encoding/json"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/knqyf263/gost/db"
	gostmodels "github.com/knqyf263/gost/models"
)

// Debian is Gost client for Debian GNU/Linux
type Debian struct {
	Base
}

type packCves struct {
	packName  string
	isSrcPack bool
	cves      []models.CveContent
}

// DetectUnfixed fills cve information that has in Gost
func (deb Debian) DetectUnfixed(driver db.DB, r *models.ScanResult, _ bool) (nCVEs int, err error) {
	linuxImage := "linux-image-" + r.RunningKernel.Release
	// Add linux and set the version of running kernel to search OVAL.
	if r.Container.ContainerID == "" {
		newVer := ""
		if p, ok := r.Packages[linuxImage]; ok {
			newVer = p.NewVersion
		}
		r.Packages["linux"] = models.Package{
			Name:       "linux",
			Version:    r.RunningKernel.Version,
			NewVersion: newVer,
		}
	}

	packCvesList := []packCves{}
	if config.Conf.Gost.IsFetchViaHTTP() {
		url, _ := util.URLPathJoin(config.Conf.Gost.URL, "debian", major(r.Release), "pkgs")
		responses, err := getAllUnfixedCvesViaHTTP(r, url)
		if err != nil {
			return 0, err
		}

		for _, res := range responses {
			debCves := map[string]gostmodels.DebianCVE{}
			if err := json.Unmarshal([]byte(res.json), &debCves); err != nil {
				return 0, err
			}
			cves := []models.CveContent{}
			for _, debcve := range debCves {
				cves = append(cves, *deb.ConvertToModel(&debcve))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  res.request.packName,
				isSrcPack: res.request.isSrcPack,
				cves:      cves,
			})
		}
	} else {
		if driver == nil {
			return 0, nil
		}
		for _, pack := range r.Packages {
			cveDebs := driver.GetUnfixedCvesDebian(major(r.Release), pack.Name)
			cves := []models.CveContent{}
			for _, cveDeb := range cveDebs {
				cves = append(cves, *deb.ConvertToModel(&cveDeb))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: false,
				cves:      cves,
			})
		}

		// SrcPack
		for _, pack := range r.SrcPackages {
			cveDebs := driver.GetUnfixedCvesDebian(major(r.Release), pack.Name)
			cves := []models.CveContent{}
			for _, cveDeb := range cveDebs {
				cves = append(cves, *deb.ConvertToModel(&cveDeb))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: true,
				cves:      cves,
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
				}
			} else {
				v = models.VulnInfo{
					CveID:       cve.CveID,
					CveContents: models.NewCveContents(cve),
					Confidences: models.Confidences{models.DebianSecurityTrackerMatch},
				}
				nCVEs++
			}

			names := []string{}
			if p.isSrcPack {
				if srcPack, ok := r.SrcPackages[p.packName]; ok {
					for _, binName := range srcPack.BinaryNames {
						if _, ok := r.Packages[binName]; ok {
							names = append(names, binName)
						}
					}
				}
			} else {
				if p.packName == "linux" {
					names = append(names, linuxImage)
				} else {
					names = append(names, p.packName)
				}
			}

			for _, name := range names {
				v.AffectedPackages = v.AffectedPackages.Store(models.PackageFixStatus{
					Name:        name,
					FixState:    "open",
					NotFixedYet: true,
				})
			}
			r.ScannedCves[cve.CveID] = v
		}
	}
	return nCVEs, nil
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
