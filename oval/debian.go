//go:build !scanner
// +build !scanner

package oval

import (
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
)

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
}

func (o DebianBase) update(r *models.ScanResult, defpacks defPacks) {
	for _, cve := range defpacks.def.Advisory.Cves {
		ovalContent := o.convertToModel(cve.CveID, &defpacks.def)
		if ovalContent == nil {
			continue
		}
		vinfo, ok := r.ScannedCves[cve.CveID]
		if !ok {
			logging.Log.Debugf("%s is newly detected by OVAL", cve.CveID)
			vinfo = models.VulnInfo{
				CveID:       cve.CveID,
				Confidences: []models.Confidence{models.OvalMatch},
				CveContents: models.NewCveContents(*ovalContent),
			}
		} else {
			cveContents := vinfo.CveContents
			if _, ok := vinfo.CveContents[ovalContent.Type]; ok {
				logging.Log.Debugf("%s OVAL will be overwritten", cve.CveID)
			} else {
				logging.Log.Debugf("%s is also detected by OVAL", cve.CveID)
				cveContents = models.CveContents{}
			}
			vinfo.Confidences.AppendIfMissing(models.OvalMatch)
			cveContents[ovalContent.Type] = []models.CveContent{*ovalContent}
			vinfo.CveContents = cveContents
		}

		// uniq(vinfo.AffectedPackages[].Name + defPacks.binpkgFixstat(map[string(=package name)]fixStat{}))
		collectBinpkgFixstat := defPacks{
			binpkgFixstat: map[string]fixStat{},
		}
		for packName, fixStatus := range defpacks.binpkgFixstat {
			collectBinpkgFixstat.binpkgFixstat[packName] = fixStatus
		}

		for _, pack := range vinfo.AffectedPackages {
			collectBinpkgFixstat.binpkgFixstat[pack.Name] = fixStat{
				notFixedYet: pack.NotFixedYet,
				fixedIn:     pack.FixedIn,
				isSrcPack:   false,
			}
		}

		// Update package status of source packages.
		// In the case of Debian based Linux, sometimes source package name is defined as affected package in OVAL.
		// To display binary package name showed in apt-get, need to convert source name to binary name.
		for binName := range defpacks.binpkgFixstat {
			if srcPack, ok := r.SrcPackages.FindByBinName(binName); ok {
				for _, p := range defpacks.def.AffectedPacks {
					if p.Name == srcPack.Name {
						collectBinpkgFixstat.binpkgFixstat[binName] = fixStat{
							notFixedYet: p.NotFixedYet,
							fixedIn:     p.Version,
							isSrcPack:   true,
							srcPackName: srcPack.Name,
						}
					}
				}
			}
		}

		vinfo.AffectedPackages = collectBinpkgFixstat.toPackStatuses()
		vinfo.AffectedPackages.Sort()
		r.ScannedCves[cve.CveID] = vinfo
	}
}

func (o DebianBase) convertToModel(cveID string, def *ovalmodels.Definition) *models.CveContent {
	refs := make([]models.Reference, 0, len(def.References))
	for _, r := range def.References {
		refs = append(refs, models.Reference{
			Link:   r.RefURL,
			Source: r.Source,
			RefID:  r.RefID,
		})
	}

	for _, cve := range def.Advisory.Cves {
		if cve.CveID != cveID {
			continue
		}

		return &models.CveContent{
			Type:          models.NewCveContentType(o.family),
			CveID:         cve.CveID,
			Title:         def.Title,
			Summary:       def.Description,
			Cvss2Severity: def.Advisory.Severity,
			Cvss3Severity: def.Advisory.Severity,
			References:    refs,
		}
	}

	return nil
}

// Debian is the interface for Debian OVAL
type Debian struct {
	DebianBase
}

// NewDebian creates OVAL client for Debian
func NewDebian(driver ovaldb.DB, baseURL string) Debian {
	return Debian{
		DebianBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Debian,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Debian) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {

	//Debian's uname gives both of kernel release(uname -r), version(kernel-image version)
	linuxImage := "linux-image-" + r.RunningKernel.Release

	// Add linux and set the version of running kernel to search OVAL.
	if r.Container.ContainerID == "" {
		if r.RunningKernel.Version != "" {
			newVer := ""
			if p, ok := r.Packages[linuxImage]; ok {
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

	var relatedDefs ovalResult
	if o.driver == nil {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.baseURL); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions via HTTP. err: %w", err)
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(r, o.driver); err != nil {
			return 0, xerrors.Errorf("Failed to get Definitions from DB. err: %w", err)
		}
	}

	delete(r.Packages, "linux")

	for _, defPacks := range relatedDefs.entries {
		// Remove "linux" added above for oval search
		// linux is not a real package name (key of affected packages in OVAL)
		if notFixedYet, ok := defPacks.binpkgFixstat["linux"]; ok {
			defPacks.binpkgFixstat[linuxImage] = notFixedYet
			delete(defPacks.binpkgFixstat, "linux")
			for i, p := range defPacks.def.AffectedPacks {
				if p.Name == "linux" {
					p.Name = linuxImage
					defPacks.def.AffectedPacks[i] = p
				}
			}
		}

		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		if conts, ok := vuln.CveContents[models.Debian]; ok {
			for i, cont := range conts {
				cont.SourceLink = "https://security-tracker.debian.org/tracker/" + cont.CveID
				vuln.CveContents[models.Debian][i] = cont
			}
		}
	}
	return len(relatedDefs.entries), nil
}

// Ubuntu is the interface for Debian OVAL
type Ubuntu struct {
	DebianBase
}

// NewUbuntu creates OVAL client for Debian
func NewUbuntu(driver ovaldb.DB, baseURL string) Ubuntu {
	return Ubuntu{
		DebianBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Ubuntu,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Ubuntu) FillWithOval(_ *models.ScanResult) (nCVEs int, err error) {
	return 0, nil
}
