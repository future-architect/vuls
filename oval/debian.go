package oval

import (
	"fmt"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/kotakanbe/goval-dictionary/db"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
}

func (o DebianBase) update(r *models.ScanResult, defPacks defPacks) {
	ovalContent := *o.convertToModel(&defPacks.def)
	ovalContent.Type = models.NewCveContentType(o.family)
	vinfo, ok := r.ScannedCves[defPacks.def.Debian.CveID]
	if !ok {
		util.Log.Debugf("%s is newly detected by OVAL", defPacks.def.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:       defPacks.def.Debian.CveID,
			Confidences: []models.Confidence{models.OvalMatch},
			CveContents: models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			util.Log.Debugf("%s OVAL will be overwritten",
				defPacks.def.Debian.CveID)
		} else {
			util.Log.Debugf("%s is also detected by OVAL",
				defPacks.def.Debian.CveID)
			cveContents = models.CveContents{}
		}
		vinfo.Confidences.AppendIfMissing(models.OvalMatch)
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}

	// uniq(vinfo.PackNames + defPacks.actuallyAffectedPackNames)
	for _, pack := range vinfo.AffectedPackages {
		defPacks.actuallyAffectedPackNames[pack.Name] = pack.NotFixedYet
	}

	// update notFixedYet of SrcPackage
	for binName := range defPacks.actuallyAffectedPackNames {
		if srcPack, ok := r.SrcPackages.FindByBinName(binName); ok {
			for _, p := range defPacks.def.AffectedPacks {
				if p.Name == srcPack.Name {
					defPacks.actuallyAffectedPackNames[binName] = p.NotFixedYet
				}
			}
		}
	}

	vinfo.AffectedPackages = defPacks.toPackStatuses()
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[defPacks.def.Debian.CveID] = vinfo
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
		CveID:         def.Debian.CveID,
		Title:         def.Title,
		Summary:       def.Description,
		Cvss2Severity: def.Advisory.Severity,
		Cvss3Severity: def.Advisory.Severity,
		References:    refs,
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
			Base{
				family: config.Debian,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Debian) FillWithOval(driver db.DB, r *models.ScanResult) (nCVEs int, err error) {

	//Debian's uname gives both of kernel release(uname -r), version(kernel-image version)
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

	var relatedDefs ovalResult
	if config.Conf.OvalDict.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return 0, err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
		}
	}

	delete(r.Packages, "linux")

	for _, defPacks := range relatedDefs.entries {
		// Remove "linux" added above for oval search
		// linux is not a real package name (key of affected packages in OVAL)
		if notFixedYet, ok := defPacks.actuallyAffectedPackNames["linux"]; ok {
			defPacks.actuallyAffectedPackNames[linuxImage] = notFixedYet
			delete(defPacks.actuallyAffectedPackNames, "linux")
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
		if cont, ok := vuln.CveContents[models.Debian]; ok {
			cont.SourceLink = "https://security-tracker.debian.org/tracker/" + cont.CveID
			vuln.CveContents[models.Debian] = cont
		}
	}
	return len(relatedDefs.entries), nil
}

// Ubuntu is the interface for Debian OVAL
type Ubuntu struct {
	DebianBase
}

// NewUbuntu creates OVAL client for Debian
func NewUbuntu() Ubuntu {
	return Ubuntu{
		DebianBase{
			Base{
				family: config.Ubuntu,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Ubuntu) FillWithOval(driver db.DB, r *models.ScanResult) (nCVEs int, err error) {
	switch major(r.Release) {
	case "14":
		kernelNamesInOval := []string{
			"linux",
			"linux-aws",
			"linux-azure",
			"linux-firmware",
			"linux-lts-utopic",
			"linux-lts-vivid",
			"linux-lts-wily",
			"linux-lts-xenial",
		}
		return o.fillWithOval(driver, r, kernelNamesInOval)
	case "16":
		kernelNamesInOval := []string{
			"linux-image-aws",
			"linux-image-aws-hwe",
			"linux-image-azure",
			"linux-image-extra-virtual",
			"linux-image-extra-virtual-lts-utopic",
			"linux-image-extra-virtual-lts-vivid",
			"linux-image-extra-virtual-lts-wily",
			"linux-image-extra-virtual-lts-xenial",
			"linux-image-gcp",
			"linux-image-generic-lpae",
			"linux-image-generic-lpae-hwe-16.04",
			"linux-image-generic-lpae-lts-utopic",
			"linux-image-generic-lpae-lts-vivid",
			"linux-image-generic-lpae-lts-wily",
			"linux-image-generic-lpae-lts-xenial",
			"linux-image-generic-lts-utopic",
			"linux-image-generic-lts-vivid",
			"linux-image-generic-lts-wily",
			"linux-image-generic-lts-xenial",
			"linux-image-gke",
			"linux-image-hwe-generic-trusty",
			"linux-image-hwe-virtual-trusty",
			"linux-image-kvm",
			"linux-image-lowlatency",
			"linux-image-lowlatency-lts-utopic",
			"linux-image-lowlatency-lts-vivid",
			"linux-image-lowlatency-lts-wily",
		}
		return o.fillWithOval(driver, r, kernelNamesInOval)
	case "18":
		kernelNamesInOval := []string{
			"linux-image-aws",
			"linux-image-azure",
			"linux-image-extra-virtual",
			"linux-image-gcp",
			"linux-image-generic-lpae",
			"linux-image-kvm",
			"linux-image-lowlatency",
			"linux-image-oem",
			"linux-image-oracle",
			"linux-image-raspi2",
			"linux-image-snapdragon",
			"linux-image-virtual",
		}
		return o.fillWithOval(driver, r, kernelNamesInOval)
	}
	return 0, fmt.Errorf("Ubuntu %s is not support for now", r.Release)
}

func (o Ubuntu) fillWithOval(driver db.DB, r *models.ScanResult, kernelNamesInOval []string) (nCVEs int, err error) {
	// kernel names in OVAL except for linux-image-generic
	linuxImage := "linux-image-" + r.RunningKernel.Release
	runningKernelVersion := ""
	kernelPkgInOVAL := ""
	isOVALKernelPkgAdded := true
	unusedKernels := []models.Package{}

	if r.Container.ContainerID == "" {
		if v, ok := r.Packages[linuxImage]; ok {
			runningKernelVersion = v.Version
		} else {
			util.Log.Warnf("Unable to detect vulns of running kernel because the version of the runnning kernel is unknown. server: %s",
				r.ServerName)
		}

		for _, n := range kernelNamesInOval {
			if p, ok := r.Packages[n]; ok {
				kernelPkgInOVAL = p.Name
				break
			}
		}

		// remove unused kernels from packages to prevent detecting vulns of unused kernel
		for _, n := range kernelNamesInOval {
			if v, ok := r.Packages[n]; ok {
				unusedKernels = append(unusedKernels, v)
				delete(r.Packages, n)
			}
		}

		if kernelPkgInOVAL == "" {
			if r.Release == "14" {
				kernelPkgInOVAL = "linux"
			} else if _, ok := r.Packages["linux-image-generic"]; !ok {
				util.Log.Warnf("The OVAL name of the running kernel image %s is not found. So vulns of linux-image-generic wll be detected. server: %s",
					r.RunningKernel.Version, r.ServerName)
				kernelPkgInOVAL = "linux-image-generic"
			} else {
				isOVALKernelPkgAdded = false
			}
		}

		if runningKernelVersion != "" {
			r.Packages[kernelPkgInOVAL] = models.Package{
				Name:    kernelPkgInOVAL,
				Version: runningKernelVersion,
			}
		}
	}

	var relatedDefs ovalResult
	if config.Conf.OvalDict.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r); err != nil {
			return 0, err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
		}
	}

	if isOVALKernelPkgAdded {
		delete(r.Packages, kernelPkgInOVAL)
	}
	for _, p := range unusedKernels {
		r.Packages[p.Name] = p
	}

	for _, defPacks := range relatedDefs.entries {
		// Remove "linux" added above to search for oval
		// "linux" is not a real package name (key of affected packages in OVAL)
		if nfy, ok := defPacks.actuallyAffectedPackNames[kernelPkgInOVAL]; isOVALKernelPkgAdded && ok {
			defPacks.actuallyAffectedPackNames[linuxImage] = nfy
			delete(defPacks.actuallyAffectedPackNames, kernelPkgInOVAL)
			for i, p := range defPacks.def.AffectedPacks {
				if p.Name == kernelPkgInOVAL {
					p.Name = linuxImage
					defPacks.def.AffectedPacks[i] = p
				}
			}
		}
		o.update(r, defPacks)
	}

	for _, vuln := range r.ScannedCves {
		if cont, ok := vuln.CveContents[models.Ubuntu]; ok {
			cont.SourceLink = "http://people.ubuntu.com/~ubuntu-security/cve/" + cont.CveID
			vuln.CveContents[models.Ubuntu] = cont
		}
	}
	return len(relatedDefs.entries), nil
}
