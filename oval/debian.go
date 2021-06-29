// +build !scanner

package oval

import (
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
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
		logging.Log.Debugf("%s is newly detected by OVAL", defPacks.def.Debian.CveID)
		vinfo = models.VulnInfo{
			CveID:       defPacks.def.Debian.CveID,
			Confidences: []models.Confidence{models.OvalMatch},
			CveContents: models.NewCveContents(ovalContent),
		}
	} else {
		cveContents := vinfo.CveContents
		ctype := models.NewCveContentType(o.family)
		if _, ok := vinfo.CveContents[ctype]; ok {
			logging.Log.Debugf("%s OVAL will be overwritten",
				defPacks.def.Debian.CveID)
		} else {
			logging.Log.Debugf("%s is also detected by OVAL",
				defPacks.def.Debian.CveID)
			cveContents = models.CveContents{}
		}
		if r.Family != constant.Raspbian {
			vinfo.Confidences.AppendIfMissing(models.OvalMatch)
		} else {
			if len(vinfo.Confidences) == 0 {
				vinfo.Confidences.AppendIfMissing(models.OvalMatch)
			}
		}
		cveContents[ctype] = ovalContent
		vinfo.CveContents = cveContents
	}

	// uniq(vinfo.PackNames + defPacks.binpkgStat)
	for _, pack := range vinfo.AffectedPackages {
		defPacks.binpkgFixstat[pack.Name] = fixStat{
			notFixedYet: pack.NotFixedYet,
			fixedIn:     pack.FixedIn,
			isSrcPack:   false,
		}
	}

	// Update package status of source packages.
	// In the case of Debian based Linux, sometimes source package name is defined as affected package in OVAL.
	// To display binary package name showed in apt-get, need to convert source name to binary name.
	for binName := range defPacks.binpkgFixstat {
		if srcPack, ok := r.SrcPackages.FindByBinName(binName); ok {
			for _, p := range defPacks.def.AffectedPacks {
				if p.Name == srcPack.Name {
					defPacks.binpkgFixstat[binName] = fixStat{
						notFixedYet: p.NotFixedYet,
						fixedIn:     p.Version,
						isSrcPack:   true,
						srcPackName: srcPack.Name,
					}
				}
			}
		}
	}

	vinfo.AffectedPackages = defPacks.toPackStatuses()
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[defPacks.def.Debian.CveID] = vinfo
}

func (o DebianBase) convertToModel(def *ovalmodels.Definition) *models.CveContent {
	refs := []models.Reference{}
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
func NewDebian(cnf config.VulnDictInterface) Debian {
	return Debian{
		DebianBase{
			Base{
				family: constant.Debian,
				Cnf:    cnf,
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
	if o.Cnf.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.Cnf.GetURL()); err != nil {
			return 0, err
		}
	} else {
		driver, err := newOvalDB(o.Cnf, r.Family)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
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
func NewUbuntu(cnf config.VulnDictInterface) Ubuntu {
	return Ubuntu{
		DebianBase{
			Base{
				family: constant.Ubuntu,
				Cnf:    cnf,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Ubuntu) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	switch util.Major(r.Release) {
	case "14":
		kernelNamesInOval := []string{
			"linux-aws",
			"linux-azure",
			"linux-lts-xenial",
			"linux-meta",
			"linux-meta-aws",
			"linux-meta-azure",
			"linux-meta-lts-xenial",
			"linux-signed",
			"linux-signed-azure",
			"linux-signed-lts-xenial",
			"linux",
		}
		return o.fillWithOval(r, kernelNamesInOval)
	case "16":
		kernelNamesInOval := []string{
			"linux-aws",
			"linux-aws-hwe",
			"linux-azure",
			"linux-euclid",
			"linux-flo",
			"linux-gcp",
			"linux-gke",
			"linux-goldfish",
			"linux-hwe",
			"linux-kvm",
			"linux-mako",
			"linux-meta",
			"linux-meta-aws",
			"linux-meta-aws-hwe",
			"linux-meta-azure",
			"linux-meta-gcp",
			"linux-meta-hwe",
			"linux-meta-kvm",
			"linux-meta-oracle",
			"linux-meta-raspi2",
			"linux-meta-snapdragon",
			"linux-oem",
			"linux-oracle",
			"linux-raspi2",
			"linux-signed",
			"linux-signed-azure",
			"linux-signed-gcp",
			"linux-signed-hwe",
			"linux-signed-oracle",
			"linux-snapdragon",
			"linux",
		}
		return o.fillWithOval(r, kernelNamesInOval)
	case "18":
		kernelNamesInOval := []string{
			"linux-aws",
			"linux-aws-5.0",
			"linux-azure",
			"linux-gcp",
			"linux-gcp-5.3",
			"linux-gke-4.15",
			"linux-gke-5.0",
			"linux-gke-5.3",
			"linux-hwe",
			"linux-kvm",
			"linux-meta",
			"linux-meta-aws",
			"linux-meta-aws-5.0",
			"linux-meta-azure",
			"linux-meta-gcp",
			"linux-meta-gcp-5.3",
			"linux-meta-gke-4.15",
			"linux-meta-gke-5.0",
			"linux-meta-gke-5.3",
			"linux-meta-hwe",
			"linux-meta-kvm",
			"linux-meta-oem",
			"linux-meta-oem-osp1",
			"linux-meta-oracle",
			"linux-meta-oracle-5.0",
			"linux-meta-oracle-5.3",
			"linux-meta-raspi2",
			"linux-meta-raspi2-5.3",
			"linux-meta-snapdragon",
			"linux-oem",
			"linux-oem-osp1",
			"linux-oracle",
			"linux-oracle-5.0",
			"linux-oracle-5.3",
			"linux-raspi2",
			"linux-raspi2-5.3",
			"linux-signed",
			"linux-signed-azure",
			"linux-signed-gcp",
			"linux-signed-gcp-5.3",
			"linux-signed-gke-4.15",
			"linux-signed-gke-5.0",
			"linux-signed-gke-5.3",
			"linux-signed-hwe",
			"linux-signed-oem",
			"linux-signed-oem-osp1",
			"linux-signed-oracle",
			"linux-signed-oracle-5.0",
			"linux-signed-oracle-5.3",
			"linux-snapdragon",
			"linux",
		}
		return o.fillWithOval(r, kernelNamesInOval)
	case "20":
		kernelNamesInOval := []string{
			"linux-aws",
			"linux-azure",
			"linux-gcp",
			"linux-kvm",
			"linux-meta",
			"linux-meta-aws",
			"linux-meta-azure",
			"linux-meta-gcp",
			"linux-meta-kvm",
			"linux-meta-oem-5.6",
			"linux-meta-oracle",
			"linux-meta-raspi",
			"linux-meta-riscv",
			"linux-oem-5.6",
			"linux-oracle",
			"linux-raspi",
			"linux-raspi2",
			"linux-riscv",
			"linux-signed",
			"linux-signed-azure",
			"linux-signed-gcp",
			"linux-signed-oem-5.6",
			"linux-signed-oracle",
			"linux",
		}
		return o.fillWithOval(r, kernelNamesInOval)
	case "21":
		kernelNamesInOval := []string{
			"linux-aws",
			"linux-base-sgx",
			"linux-base",
			"linux-cloud-tools-common",
			"linux-cloud-tools-generic",
			"linux-cloud-tools-lowlatency",
			"linux-cloud-tools-virtual",
			"linux-gcp",
			"linux-generic",
			"linux-gke",
			"linux-headers-aws",
			"linux-headers-gcp",
			"linux-headers-gke",
			"linux-headers-oracle",
			"linux-image-aws",
			"linux-image-extra-virtual",
			"linux-image-gcp",
			"linux-image-generic",
			"linux-image-gke",
			"linux-image-lowlatency",
			"linux-image-oracle",
			"linux-image-virtual",
			"linux-lowlatency",
			"linux-modules-extra-aws",
			"linux-modules-extra-gcp",
			"linux-modules-extra-gke",
			"linux-oracle",
			"linux-tools-aws",
			"linux-tools-common",
			"linux-tools-gcp",
			"linux-tools-generic",
			"linux-tools-gke",
			"linux-tools-host",
			"linux-tools-lowlatency",
			"linux-tools-oracle",
			"linux-tools-virtual",
			"linux-virtual",
		}
		return o.fillWithOval(r, kernelNamesInOval)
	}
	return 0, fmt.Errorf("Ubuntu %s is not support for now", r.Release)
}

func (o Ubuntu) fillWithOval(r *models.ScanResult, kernelNamesInOval []string) (nCVEs int, err error) {
	linuxImage := "linux-image-" + r.RunningKernel.Release
	runningKernelVersion := ""
	kernelPkgInOVAL := ""
	isOVALKernelPkgAdded := false
	unusedKernels := []models.Package{}
	copiedSourcePkgs := models.SrcPackages{}

	if r.Container.ContainerID == "" {
		if v, ok := r.Packages[linuxImage]; ok {
			runningKernelVersion = v.Version
		} else {
			logging.Log.Warnf("Unable to detect vulns of running kernel because the version of the running kernel is unknown. server: %s",
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

		// Remove linux-* in order to detect only vulnerabilities in the running kernel.
		for n := range r.Packages {
			if n != kernelPkgInOVAL && strings.HasPrefix(n, "linux-") {
				unusedKernels = append(unusedKernels, r.Packages[n])
				delete(r.Packages, n)
			}
		}
		for srcPackName, srcPack := range r.SrcPackages {
			copiedSourcePkgs[srcPackName] = srcPack
			targetBinaryNames := []string{}
			for _, n := range srcPack.BinaryNames {
				if n == kernelPkgInOVAL || !strings.HasPrefix(n, "linux-") {
					targetBinaryNames = append(targetBinaryNames, n)
				}
			}
			srcPack.BinaryNames = targetBinaryNames
			r.SrcPackages[srcPackName] = srcPack
		}

		if kernelPkgInOVAL == "" {
			logging.Log.Warnf("The OVAL name of the running kernel image %+v is not found. So vulns of `linux` wll be detected. server: %s",
				r.RunningKernel, r.ServerName)
			kernelPkgInOVAL = "linux"
			isOVALKernelPkgAdded = true
		}

		if runningKernelVersion != "" {
			r.Packages[kernelPkgInOVAL] = models.Package{
				Name:    kernelPkgInOVAL,
				Version: runningKernelVersion,
			}
		}
	}

	var relatedDefs ovalResult
	if o.Cnf.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.Cnf.GetURL()); err != nil {
			return 0, err
		}
	} else {
		driver, err := newOvalDB(o.Cnf, r.Family)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

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
	r.SrcPackages = copiedSourcePkgs

	for _, defPacks := range relatedDefs.entries {
		// Remove "linux" added above for searching oval
		// "linux" is not a real package name (key of affected packages in OVAL)
		if nfy, ok := defPacks.binpkgFixstat[kernelPkgInOVAL]; isOVALKernelPkgAdded && ok {
			defPacks.binpkgFixstat[linuxImage] = nfy
			delete(defPacks.binpkgFixstat, kernelPkgInOVAL)
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
