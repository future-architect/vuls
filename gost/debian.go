//go:build !scanner
// +build !scanner

package gost

import (
	"encoding/json"

	debver "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	gostmodels "github.com/vulsio/gost/models"
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
		"11": "bullseye",
	}[major]
	return ok
}

// DetectCVEs fills cve information that has in Gost
func (deb Debian) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	if !deb.supported(major(r.Release)) {
		// only logging
		logging.Log.Warnf("Debian %s is not supported yet", r.Release)
		return 0, nil
	}

	// Add linux and set the version of running kernel to search Gost.
	if r.Container.ContainerID == "" {
		if r.RunningKernel.Version != "" {
			newVer := ""
			if p, ok := r.Packages["linux-image-"+r.RunningKernel.Release]; ok {
				newVer = p.NewVersion
			}
			r.Packages["linux"] = models.Package{
				Name:       "linux",
				Version:    r.RunningKernel.Version,
				NewVersion: newVer,
			}
		} else {
			logging.Log.Warnf("Since the exact kernel version is not available, the vulnerability in the linux package is not detected.")
		}
	}

	var stashLinuxPackage models.Package
	if linux, ok := r.Packages["linux"]; ok {
		stashLinuxPackage = linux
	}
	nFixedCVEs, err := deb.detectCVEsWithFixState(r, "resolved")
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect fixed CVEs. err: %w", err)
	}

	if stashLinuxPackage.Name != "" {
		r.Packages["linux"] = stashLinuxPackage
	}
	nUnfixedCVEs, err := deb.detectCVEsWithFixState(r, "open")
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect unfixed CVEs. err: %w", err)
	}

	return (nFixedCVEs + nUnfixedCVEs), nil
}

func (deb Debian) detectCVEsWithFixState(r *models.ScanResult, fixStatus string) (nCVEs int, err error) {
	if fixStatus != "resolved" && fixStatus != "open" {
		return 0, xerrors.Errorf(`Failed to detectCVEsWithFixState. fixStatus is not allowed except "open" and "resolved"(actual: fixStatus -> %s).`, fixStatus)
	}

	packCvesList := []packCves{}
	if deb.driver == nil {
		url, err := util.URLPathJoin(deb.baseURL, "debian", major(r.Release), "pkgs")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}

		s := "unfixed-cves"
		if s == "resolved" {
			s = "fixed-cves"
		}
		responses, err := getCvesWithFixStateViaHTTP(r, url, s)
		if err != nil {
			return 0, xerrors.Errorf("Failed to get CVEs via HTTP. err: %w", err)
		}

		for _, res := range responses {
			debCves := map[string]gostmodels.DebianCVE{}
			if err := json.Unmarshal([]byte(res.json), &debCves); err != nil {
				return 0, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
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
		for _, pack := range r.Packages {
			cves, fixes, err := deb.getCvesDebianWithfixStatus(fixStatus, major(r.Release), pack.Name)
			if err != nil {
				return 0, xerrors.Errorf("Failed to get CVEs for Package. err: %w", err)
			}
			packCvesList = append(packCvesList, packCves{
				packName:  pack.Name,
				isSrcPack: false,
				cves:      cves,
				fixes:     fixes,
			})
		}

		// SrcPack
		for _, pack := range r.SrcPackages {
			cves, fixes, err := deb.getCvesDebianWithfixStatus(fixStatus, major(r.Release), pack.Name)
			if err != nil {
				return 0, xerrors.Errorf("Failed to get CVEs for SrcPackage. err: %w", err)
			}
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
		for i, cve := range p.cves {
			v, ok := r.ScannedCves[cve.CveID]
			if ok {
				if v.CveContents == nil {
					v.CveContents = models.NewCveContents(cve)
				} else {
					v.CveContents[models.DebianSecurityTracker] = []models.CveContent{cve}
					v.Confidences = models.Confidences{models.DebianSecurityTrackerMatch}
				}
			} else {
				v = models.VulnInfo{
					CveID:       cve.CveID,
					CveContents: models.NewCveContents(cve),
					Confidences: models.Confidences{models.DebianSecurityTrackerMatch},
				}

				if fixStatus == "resolved" {
					versionRelease := ""
					if p.isSrcPack {
						versionRelease = r.SrcPackages[p.packName].Version
					} else {
						versionRelease = r.Packages[p.packName].FormatVer()
					}

					if versionRelease == "" {
						break
					}

					affected, err := isGostDefAffected(versionRelease, p.fixes[i].FixedIn)
					if err != nil {
						logging.Log.Debugf("Failed to parse versions: %s, Ver: %s, Gost: %s",
							err, versionRelease, p.fixes[i].FixedIn)
						continue
					}

					if !affected {
						continue
					}
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
					names = append(names, "linux-image-"+r.RunningKernel.Release)
				} else {
					names = append(names, p.packName)
				}
			}

			if fixStatus == "resolved" {
				for _, name := range names {
					v.AffectedPackages = v.AffectedPackages.Store(models.PackageFixStatus{
						Name:    name,
						FixedIn: p.fixes[i].FixedIn,
					})
				}
			} else {
				for _, name := range names {
					v.AffectedPackages = v.AffectedPackages.Store(models.PackageFixStatus{
						Name:        name,
						FixState:    "open",
						NotFixedYet: true,
					})
				}
			}

			r.ScannedCves[cve.CveID] = v
		}
	}

	return nCVEs, nil
}

func isGostDefAffected(versionRelease, gostVersion string) (affected bool, err error) {
	vera, err := debver.NewVersion(versionRelease)
	if err != nil {
		return false, xerrors.Errorf("Failed to parse version. version: %s, err: %w", versionRelease, err)
	}
	verb, err := debver.NewVersion(gostVersion)
	if err != nil {
		return false, xerrors.Errorf("Failed to parse version. version: %s, err: %w", gostVersion, err)
	}
	return vera.LessThan(verb), nil
}

func (deb Debian) getCvesDebianWithfixStatus(fixStatus, release, pkgName string) ([]models.CveContent, []models.PackageFixStatus, error) {
	var f func(string, string) (map[string]gostmodels.DebianCVE, error)
	if fixStatus == "resolved" {
		f = deb.driver.GetFixedCvesDebian
	} else {
		f = deb.driver.GetUnfixedCvesDebian
	}
	debCves, err := f(release, pkgName)
	if err != nil {
		return nil, nil, xerrors.Errorf("Failed to get CVEs. fixStatus: %s, release: %s, src package: %s, err: %w", fixStatus, release, pkgName, err)
	}

	cves := []models.CveContent{}
	fixes := []models.PackageFixStatus{}
	for _, devbCve := range debCves {
		cves = append(cves, *deb.ConvertToModel(&devbCve))
		fixes = append(fixes, checkPackageFixStatus(&devbCve)...)
	}
	return cves, fixes, nil
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

func checkPackageFixStatus(cve *gostmodels.DebianCVE) []models.PackageFixStatus {
	fixes := []models.PackageFixStatus{}
	for _, p := range cve.Package {
		for _, r := range p.Release {
			f := models.PackageFixStatus{Name: p.PackageName}

			if r.Status == "open" {
				f.NotFixedYet = true
			} else {
				f.FixedIn = r.FixedVersion
			}

			fixes = append(fixes, f)
		}
	}

	return fixes
}
