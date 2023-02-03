//go:build !scanner
// +build !scanner

package gost

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	gostmodels "github.com/vulsio/gost/models"
)

// Ubuntu is Gost client for Ubuntu
type Ubuntu struct {
	Base
}

func (ubu Ubuntu) supported(version string) bool {
	_, ok := map[string]string{
		"606":  "dapper",
		"610":  "edgy",
		"704":  "feisty",
		"710":  "gutsy",
		"804":  "hardy",
		"810":  "intrepid",
		"904":  "jaunty",
		"910":  "karmic",
		"1004": "lucid",
		"1010": "maverick",
		"1104": "natty",
		"1110": "oneiric",
		"1204": "precise",
		"1210": "quantal",
		"1304": "raring",
		"1310": "saucy",
		"1404": "trusty",
		"1410": "utopic",
		"1504": "vivid",
		"1510": "wily",
		"1604": "xenial",
		"1610": "yakkety",
		"1704": "zesty",
		"1710": "artful",
		"1804": "bionic",
		"1810": "cosmic",
		"1904": "disco",
		"1910": "eoan",
		"2004": "focal",
		"2010": "groovy",
		"2104": "hirsute",
		"2110": "impish",
		"2204": "jammy",
		"2210": "kinetic",
		// "2304": "lunar",
	}[version]
	return ok
}

type cveContent struct {
	cveContent  models.CveContent
	fixStatuses models.PackageFixStatuses
}

var kernelSourceNamePattern = regexp.MustCompile(`^linux((-(ti-omap4|armadaxp|mako|manta|flo|goldfish|joule|raspi2?|snapdragon|aws|azure|bluefield|dell300x|gcp|gke(op)?|ibm|intel|lowlatency|kvm|oem|oracle|euclid|lts-xenial|hwe|riscv))?(-(edge|fde|iotg|hwe|osp1))?(-[\d\.]+)?)?$`)

// DetectCVEs fills cve information that has in Gost
func (ubu Ubuntu) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	ubuReleaseVer := strings.Replace(r.Release, ".", "", 1)
	if !ubu.supported(ubuReleaseVer) {
		logging.Log.Warnf("Ubuntu %s is not supported yet", r.Release)
		return 0, nil
	}

	detects := map[string]cveContent{}
	if ubu.driver == nil {
		urlPrefix, err := util.URLPathJoin(ubu.baseURL, "ubuntu", ubuReleaseVer, "pkgs")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}
		responses, err := getCvesWithFixStateViaHTTP(r, urlPrefix, "fixed-cves")
		if err != nil {
			return 0, xerrors.Errorf("Failed to get fixed CVEs via HTTP. err: %w", err)
		}

		for _, res := range responses {
			if !res.request.isSrcPack {
				continue
			}

			n := strings.NewReplacer("linux-signed", "linux", "linux-meta", "linux").Replace(res.request.packName)

			if kernelSourceNamePattern.MatchString(n) {
				isDetect := false
				for _, bn := range r.SrcPackages[res.request.packName].BinaryNames {
					if bn == fmt.Sprintf("linux-image-%s", r.RunningKernel.Release) {
						isDetect = true
						break
					}
				}
				if !isDetect {
					continue
				}
			}

			fixeds := map[string]gostmodels.UbuntuCVE{}
			if err := json.Unmarshal([]byte(res.json), &fixeds); err != nil {
				return 0, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
			}
			for _, content := range detect(fixeds, true, models.SrcPackage{Name: res.request.packName, Version: r.SrcPackages[res.request.packName].Version, BinaryNames: r.SrcPackages[res.request.packName].BinaryNames}, fmt.Sprintf("linux-image-%s", r.RunningKernel.Release)) {
				c, ok := detects[content.cveContent.CveID]
				if ok {
					content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
				}
				detects[content.cveContent.CveID] = content
			}
		}

		responses, err = getCvesWithFixStateViaHTTP(r, urlPrefix, "unfixed-cves")
		if err != nil {
			return 0, xerrors.Errorf("Failed to get unfixed CVEs via HTTP. err: %w", err)
		}
		for _, res := range responses {
			if !res.request.isSrcPack {
				continue
			}

			n := strings.NewReplacer("linux-signed", "linux", "linux-meta", "linux").Replace(res.request.packName)

			if kernelSourceNamePattern.MatchString(n) {
				isDetect := false
				for _, bn := range r.SrcPackages[res.request.packName].BinaryNames {
					if bn == fmt.Sprintf("linux-image-%s", r.RunningKernel.Release) {
						isDetect = true
						break
					}
				}
				if !isDetect {
					continue
				}
			}

			unfixeds := map[string]gostmodels.UbuntuCVE{}
			if err := json.Unmarshal([]byte(res.json), &unfixeds); err != nil {
				return 0, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
			}
			for _, content := range detect(unfixeds, false, models.SrcPackage{Name: res.request.packName, Version: r.SrcPackages[res.request.packName].Version, BinaryNames: r.SrcPackages[res.request.packName].BinaryNames}, fmt.Sprintf("linux-image-%s", r.RunningKernel.Release)) {
				c, ok := detects[content.cveContent.CveID]
				if ok {
					content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
				}
				detects[content.cveContent.CveID] = content
			}
		}
	} else {
		for _, pack := range r.SrcPackages {
			n := strings.NewReplacer("linux-signed", "linux", "linux-meta", "linux").Replace(pack.Name)

			if kernelSourceNamePattern.MatchString(n) {
				isDetect := false
				for _, bn := range pack.BinaryNames {
					if bn == fmt.Sprintf("linux-image-%s", r.RunningKernel.Release) {
						isDetect = true
						break
					}
				}
				if !isDetect {
					continue
				}
			}

			fixeds, err := ubu.driver.GetFixedCvesUbuntu(ubuReleaseVer, n)
			if err != nil {
				return 0, xerrors.Errorf("Failed to get fixed CVEs for SrcPackage. err: %w", err)
			}
			for _, content := range detect(fixeds, true, pack, fmt.Sprintf("linux-image-%s", r.RunningKernel.Release)) {
				c, ok := detects[content.cveContent.CveID]
				if ok {
					content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
				}
				detects[content.cveContent.CveID] = content
			}

			unfixeds, err := ubu.driver.GetUnfixedCvesUbuntu(ubuReleaseVer, n)
			if err != nil {
				return 0, xerrors.Errorf("Failed to get unfixed CVEs for SrcPackage. err: %w", err)
			}
			for _, content := range detect(unfixeds, false, pack, fmt.Sprintf("linux-image-%s", r.RunningKernel.Release)) {
				c, ok := detects[content.cveContent.CveID]
				if ok {
					content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
				}
				detects[content.cveContent.CveID] = content
			}
		}
	}

	for _, content := range detects {
		v, ok := r.ScannedCves[content.cveContent.CveID]
		if ok {
			if v.CveContents == nil {
				v.CveContents = models.NewCveContents(content.cveContent)
			} else {
				v.CveContents[models.UbuntuAPI] = []models.CveContent{content.cveContent}
				v.Confidences = models.Confidences{models.UbuntuAPIMatch}
			}
		} else {
			v = models.VulnInfo{
				CveID:       content.cveContent.CveID,
				CveContents: models.NewCveContents(content.cveContent),
				Confidences: models.Confidences{models.UbuntuAPIMatch},
			}
		}

		for _, s := range content.fixStatuses {
			v.AffectedPackages = v.AffectedPackages.Store(s)
		}
		r.ScannedCves[content.cveContent.CveID] = v
	}

	return len(detects), nil
}

func detect(cves map[string]gostmodels.UbuntuCVE, fixed bool, srcPkg models.SrcPackage, runningKernelBinaryPkgName string) []cveContent {
	n := strings.NewReplacer("linux-signed", "linux", "linux-meta", "linux").Replace(srcPkg.Name)

	var contents []cveContent
	for _, cve := range cves {
		c := cveContent{
			cveContent: *convertToModel(&cve),
		}

		if fixed {
			for _, p := range cve.Patches {
				for _, rp := range p.ReleasePatches {
					installedVersion := srcPkg.Version
					patchedVersion := rp.Note

					// https://git.launchpad.net/ubuntu-cve-tracker/tree/scripts/generate-oval#n384
					if kernelSourceNamePattern.MatchString(n) && strings.HasPrefix(srcPkg.Name, "linux-meta") {
						// 5.15.0.1026.30~20.04.16 -> 5.15.0.1026
						ss := strings.Split(installedVersion, ".")
						if len(ss) >= 4 {
							installedVersion = strings.Join(ss[:4], ".")
						}

						// 5.15.0-1026.30~20.04.16 -> 5.15.0.1026
						lhs, rhs, ok := strings.Cut(patchedVersion, "-")
						if ok {
							patchedVersion = fmt.Sprintf("%s.%s", lhs, strings.Split(rhs, ".")[0])
						}
					}

					affected, err := isGostDefAffected(installedVersion, patchedVersion)
					if err != nil {
						logging.Log.Debugf("Failed to parse versions: %s, Ver: %s, Gost: %s", err, installedVersion, patchedVersion)
						continue
					}

					if affected {
						for _, bn := range srcPkg.BinaryNames {
							if kernelSourceNamePattern.MatchString(n) && bn != runningKernelBinaryPkgName {
								continue
							}
							c.fixStatuses = append(c.fixStatuses, models.PackageFixStatus{
								Name:    bn,
								FixedIn: patchedVersion,
							})
						}
					}
				}
			}
		} else {
			for _, bn := range srcPkg.BinaryNames {
				if kernelSourceNamePattern.MatchString(n) && bn != runningKernelBinaryPkgName {
					continue
				}
				c.fixStatuses = append(c.fixStatuses, models.PackageFixStatus{
					Name:        bn,
					FixState:    "open",
					NotFixedYet: true,
				})
			}
		}

		if len(c.fixStatuses) > 0 {
			contents = append(contents, c)
		}
	}
	return contents
}

func convertToModel(cve *gostmodels.UbuntuCVE) *models.CveContent {
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
