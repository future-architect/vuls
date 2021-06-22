// +build !scanner

package gost

import (
	"encoding/json"
	"strings"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	gostmodels "github.com/knqyf263/gost/models"
)

// Ubuntu is Gost client for Ubuntu
type Ubuntu struct {
	Base
}

func (ubu Ubuntu) supported(version string) bool {
	_, ok := map[string]string{
		"1404": "trusty",
		"1604": "xenial",
		"1804": "bionic",
		"2004": "focal",
		"2010": "groovy",
		"2104": "hirsute",
	}[version]
	return ok
}

// DetectCVEs fills cve information that has in Gost
func (ubu Ubuntu) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	ubuReleaseVer := strings.Replace(r.Release, ".", "", 1)
	if !ubu.supported(ubuReleaseVer) {
		logging.Log.Warnf("Ubuntu %s is not supported yet", r.Release)
		return 0, nil
	}

	linuxImage := "linux-image-" + r.RunningKernel.Release
	// Add linux and set the version of running kernel to search Gost.
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
	if ubu.DBDriver.Cnf.IsFetchViaHTTP() {
		url, _ := util.URLPathJoin(ubu.DBDriver.Cnf.GetURL(), "ubuntu", ubuReleaseVer, "pkg")
		responses, err := getAllUnfixedCvesViaHTTP(r, url)
		if err != nil {
			return 0, err
		}

		for _, res := range responses {
			ubuCves := map[string]gostmodels.UbuntuCVE{}
			if err := json.Unmarshal([]byte(res.json), &ubuCves); err != nil {
				return 0, err
			}
			cves := []models.CveContent{}
			for _, ubucve := range ubuCves {
				cves = append(cves, *ubu.ConvertToModel(&ubucve))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  res.request.packName,
				isSrcPack: res.request.isSrcPack,
				cves:      cves,
			})
		}
	} else {
		if ubu.DBDriver.DB == nil {
			return 0, nil
		}
		for _, pack := range r.Packages {
			ubuCves := ubu.DBDriver.DB.GetUnfixedCvesUbuntu(ubuReleaseVer, pack.Name)
			cves := []models.CveContent{}
			for _, ubucve := range ubuCves {
				cves = append(cves, *ubu.ConvertToModel(&ubucve))
			}
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: false,
				cves:      cves,
			})
		}

		// SrcPack
		for _, pack := range r.SrcPackages {
			ubuCves := ubu.DBDriver.DB.GetUnfixedCvesUbuntu(ubuReleaseVer, pack.Name)
			cves := []models.CveContent{}
			for _, ubucve := range ubuCves {
				cves = append(cves, *ubu.ConvertToModel(&ubucve))
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
					v.CveContents[models.UbuntuAPI] = cve
				}
			} else {
				v = models.VulnInfo{
					CveID:       cve.CveID,
					CveContents: models.NewCveContents(cve),
					Confidences: models.Confidences{models.UbuntuAPIMatch},
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
func (ubu Ubuntu) ConvertToModel(cve *gostmodels.UbuntuCVE) *models.CveContent {
	references := []models.Reference{}
	for _, r := range cve.References {
		if strings.Contains(r.Reference, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=") {
			references = append(references, models.Reference{Source: "CVE", Link: r.Reference})
		} else {
			references = append(references, models.Reference{Link: r.Reference})
		}
	}

	for _, b := range cve.Bugs {
		references = append(references, models.Reference{Source: "Bug", Link: b.Bug})
	}

	for _, u := range cve.Upstreams {
		for _, upstreamLink := range u.UpstreamLinks {
			references = append(references, models.Reference{Source: "UPSTREAM", Link: upstreamLink.Link})
		}
	}

	return &models.CveContent{
		Type:          models.UbuntuAPI,
		CveID:         cve.Candidate,
		Summary:       cve.Description,
		Cvss2Severity: cve.Priority,
		Cvss3Severity: cve.Priority,
		SourceLink:    "https://ubuntu.com/security/" + cve.Candidate,
		References:    references,
		Published:     cve.PublicDate,
	}
}
