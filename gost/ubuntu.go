//go:build !scanner
// +build !scanner

package gost

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	debver "github.com/knqyf263/go-deb-version"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
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
		"2304": "lunar",
		"2310": "mantic",
		"2404": "noble",
	}[version]
	return ok
}

type cveContent struct {
	cveContent  models.CveContent
	fixStatuses models.PackageFixStatuses
}

// DetectCVEs fills cve information that has in Gost
func (ubu Ubuntu) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	if !ubu.supported(strings.Replace(r.Release, ".", "", 1)) {
		logging.Log.Warnf("Ubuntu %s is not supported yet", r.Release)
		return 0, nil
	}

	if r.Container.ContainerID == "" {
		if r.RunningKernel.Release == "" {
			logging.Log.Warnf("Since the exact kernel release is not available, the vulnerability in the kernel package is not detected.")
		}
	}

	fixedCVEs, err := ubu.detectCVEsWithFixState(r, true)
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect fixed CVEs. err: %w", err)
	}

	unfixedCVEs, err := ubu.detectCVEsWithFixState(r, false)
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect unfixed CVEs. err: %w", err)
	}

	return len(unique(append(fixedCVEs, unfixedCVEs...))), nil
}

func (ubu Ubuntu) detectCVEsWithFixState(r *models.ScanResult, fixed bool) ([]string, error) {
	detects := map[string]cveContent{}
	if ubu.driver == nil {
		urlPrefix, err := util.URLPathJoin(ubu.baseURL, "ubuntu", strings.Replace(r.Release, ".", "", 1), "pkgs")
		if err != nil {
			return nil, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}
		s := "fixed-cves"
		if !fixed {
			s = "unfixed-cves"
		}
		responses, err := getCvesWithFixStateViaHTTP(r, urlPrefix, s)
		if err != nil {
			return nil, xerrors.Errorf("Failed to get fixed CVEs via HTTP. err: %w", err)
		}

		for _, res := range responses {
			if !res.request.isSrcPack {
				continue
			}

			// To detect vulnerabilities in running kernels only, skip if the kernel is not running.
			if models.IsKernelSourcePackage(constant.Ubuntu, res.request.packName) && !slices.ContainsFunc(r.SrcPackages[res.request.packName].BinaryNames, func(bn string) bool {
				switch bn {
				case fmt.Sprintf("linux-image-%s", r.RunningKernel.Release), fmt.Sprintf("linux-image-unsigned-%s", r.RunningKernel.Release), fmt.Sprintf("linux-signed-image-%s", r.RunningKernel.Release), fmt.Sprintf("linux-image-uc-%s", r.RunningKernel.Release),
					fmt.Sprintf("linux-buildinfo-%s", r.RunningKernel.Release), fmt.Sprintf("linux-cloud-tools-%s", r.RunningKernel.Release), fmt.Sprintf("linux-headers-%s", r.RunningKernel.Release), fmt.Sprintf("linux-lib-rust-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-extra-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-ipu6-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-ivsc-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-iwlwifi-%s", r.RunningKernel.Release), fmt.Sprintf("linux-tools-%s", r.RunningKernel.Release):
					return true
				default:
					if (strings.HasPrefix(bn, "linux-modules-nvidia-") || strings.HasPrefix(bn, "linux-objects-nvidia-") || strings.HasPrefix(bn, "linux-signatures-nvidia-")) && strings.HasSuffix(bn, r.RunningKernel.Release) {
						return true
					}
					return false
				}
			}) {
				continue
			}

			cs := map[string]gostmodels.UbuntuCVE{}
			if err := json.Unmarshal([]byte(res.json), &cs); err != nil {
				return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
			}
			for _, content := range ubu.detect(cs, fixed, models.SrcPackage{Name: res.request.packName, Version: r.SrcPackages[res.request.packName].Version, BinaryNames: r.SrcPackages[res.request.packName].BinaryNames}) {
				c, ok := detects[content.cveContent.CveID]
				if ok {
					content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
				}
				detects[content.cveContent.CveID] = content
			}
		}
	} else {
		for _, p := range r.SrcPackages {
			// To detect vulnerabilities in running kernels only, skip if the kernel is not running.
			if models.IsKernelSourcePackage(constant.Ubuntu, p.Name) && !slices.ContainsFunc(p.BinaryNames, func(bn string) bool {
				switch bn {
				case fmt.Sprintf("linux-image-%s", r.RunningKernel.Release), fmt.Sprintf("linux-image-unsigned-%s", r.RunningKernel.Release), fmt.Sprintf("linux-signed-image-%s", r.RunningKernel.Release), fmt.Sprintf("linux-image-uc-%s", r.RunningKernel.Release),
					fmt.Sprintf("linux-buildinfo-%s", r.RunningKernel.Release), fmt.Sprintf("linux-cloud-tools-%s", r.RunningKernel.Release), fmt.Sprintf("linux-headers-%s", r.RunningKernel.Release), fmt.Sprintf("linux-lib-rust-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-extra-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-ipu6-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-ivsc-%s", r.RunningKernel.Release), fmt.Sprintf("linux-modules-iwlwifi-%s", r.RunningKernel.Release), fmt.Sprintf("linux-tools-%s", r.RunningKernel.Release):
					return true
				default:
					if (strings.HasPrefix(bn, "linux-modules-nvidia-") || strings.HasPrefix(bn, "linux-objects-nvidia-") || strings.HasPrefix(bn, "linux-signatures-nvidia-")) && strings.HasSuffix(bn, r.RunningKernel.Release) {
						return true
					}
					return false
				}
			}) {
				continue
			}

			var f func(string, string) (map[string]gostmodels.UbuntuCVE, error) = ubu.driver.GetFixedCvesUbuntu
			if !fixed {
				f = ubu.driver.GetUnfixedCvesUbuntu
			}

			n := p.Name
			if models.IsKernelSourcePackage(constant.Ubuntu, p.Name) {
				n = models.RenameKernelSourcePackageName(constant.Ubuntu, p.Name)
			}

			cs, err := f(strings.Replace(r.Release, ".", "", 1), n)
			if err != nil {
				return nil, xerrors.Errorf("Failed to get CVEs. release: %s, src package: %s, err: %w", major(r.Release), p.Name, err)
			}
			for _, content := range ubu.detect(cs, fixed, p) {
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
			}
			v.Confidences.AppendIfMissing(models.UbuntuAPIMatch)
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

	return maps.Keys(detects), nil
}

func (ubu Ubuntu) detect(cves map[string]gostmodels.UbuntuCVE, fixed bool, srcPkg models.SrcPackage) []cveContent {
	var contents []cveContent
	for _, cve := range cves {
		c := cveContent{
			cveContent: *(Ubuntu{}).ConvertToModel(&cve),
		}

		if fixed {
			for _, p := range cve.Patches {
				for _, rp := range p.ReleasePatches {
					affected, err := ubu.isGostDefAffected(srcPkg.Version, rp.Note)
					if err != nil {
						logging.Log.Debugf("Failed to parse versions: %s, Ver: %s, Gost: %s", err, srcPkg.Version, rp.Note)
						continue
					}

					if affected {
						for _, bn := range srcPkg.BinaryNames {
							c.fixStatuses = append(c.fixStatuses, models.PackageFixStatus{
								Name:    bn,
								FixedIn: rp.Note,
							})
						}
					}
				}
			}
		} else {
			for _, bn := range srcPkg.BinaryNames {
				c.fixStatuses = append(c.fixStatuses, models.PackageFixStatus{
					Name:        bn,
					FixState:    "open",
					NotFixedYet: true,
				})
			}
		}

		if len(c.fixStatuses) > 0 {
			c.fixStatuses.Sort()
			contents = append(contents, c)
		}
	}
	return contents
}

func (ubu Ubuntu) isGostDefAffected(versionRelease, gostVersion string) (affected bool, err error) {
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
		SourceLink:    fmt.Sprintf("https://ubuntu.com/security/%s", cve.Candidate),
		References:    references,
		Published:     cve.PublicDate,
	}
}
