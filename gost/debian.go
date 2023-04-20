//go:build !scanner
// +build !scanner

package gost

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	debver "github.com/knqyf263/go-deb-version"
	"golang.org/x/exp/maps"
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

func (deb Debian) supported(major string) bool {
	_, ok := map[string]string{
		"7":  "wheezy",
		"8":  "jessie",
		"9":  "stretch",
		"10": "buster",
		"11": "bullseye",
		// "12": "bookworm",
		// "13": "trixie",
		// "14": "forky",
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

	if r.Container.ContainerID == "" {
		if r.RunningKernel.Release == "" {
			logging.Log.Warnf("Since the exact kernel release is not available, the vulnerability in the kernel package is not detected.")
		}
	}

	fixedCVEs, err := deb.detectCVEsWithFixState(r, true)
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect fixed CVEs. err: %w", err)
	}

	unfixedCVEs, err := deb.detectCVEsWithFixState(r, false)
	if err != nil {
		return 0, xerrors.Errorf("Failed to detect unfixed CVEs. err: %w", err)
	}

	return len(unique(append(fixedCVEs, unfixedCVEs...))), nil
}

func (deb Debian) detectCVEsWithFixState(r *models.ScanResult, fixed bool) ([]string, error) {
	detects := map[string]cveContent{}
	if deb.driver == nil {
		urlPrefix, err := util.URLPathJoin(deb.baseURL, "debian", major(r.Release), "pkgs")
		if err != nil {
			return nil, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}
		s := "fixed-cves"
		if !fixed {
			s = "unfixed-cves"
		}
		responses, err := getCvesWithFixStateViaHTTP(r, urlPrefix, s)
		if err != nil {
			return nil, xerrors.Errorf("Failed to get CVEs via HTTP. err: %w", err)
		}

		for _, res := range responses {
			if !res.request.isSrcPack {
				continue
			}

			n := strings.NewReplacer("linux-signed", "linux", "linux-latest", "linux", "-amd64", "", "-arm64", "", "-i386", "").Replace(res.request.packName)

			if deb.isKernelSourcePackage(n) {
				isRunning := false
				for _, bn := range r.SrcPackages[res.request.packName].BinaryNames {
					if bn == fmt.Sprintf("linux-image-%s", r.RunningKernel.Release) {
						isRunning = true
						break
					}
				}
				// To detect vulnerabilities in running kernels only, skip if the kernel is not running.
				if !isRunning {
					continue
				}
			}

			cs := map[string]gostmodels.DebianCVE{}
			if err := json.Unmarshal([]byte(res.json), &cs); err != nil {
				return nil, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
			}
			for _, content := range deb.detect(cs, models.SrcPackage{Name: res.request.packName, Version: r.SrcPackages[res.request.packName].Version, BinaryNames: r.SrcPackages[res.request.packName].BinaryNames}, models.Kernel{Release: r.RunningKernel.Release, Version: r.Packages[fmt.Sprintf("linux-image-%s", r.RunningKernel.Release)].Version}) {
				c, ok := detects[content.cveContent.CveID]
				if ok {
					content.fixStatuses = append(content.fixStatuses, c.fixStatuses...)
				}
				detects[content.cveContent.CveID] = content
			}
		}
	} else {
		for _, p := range r.SrcPackages {
			n := strings.NewReplacer("linux-signed", "linux", "linux-latest", "linux", "-amd64", "", "-arm64", "", "-i386", "").Replace(p.Name)

			if deb.isKernelSourcePackage(n) {
				isRunning := false
				for _, bn := range p.BinaryNames {
					if bn == fmt.Sprintf("linux-image-%s", r.RunningKernel.Release) {
						isRunning = true
						break
					}
				}
				// To detect vulnerabilities in running kernels only, skip if the kernel is not running.
				if !isRunning {
					continue
				}
			}

			var f func(string, string) (map[string]gostmodels.DebianCVE, error) = deb.driver.GetFixedCvesDebian
			if !fixed {
				f = deb.driver.GetUnfixedCvesDebian
			}
			cs, err := f(major(r.Release), n)
			if err != nil {
				return nil, xerrors.Errorf("Failed to get CVEs. release: %s, src package: %s, err: %w", major(r.Release), p.Name, err)
			}
			for _, content := range deb.detect(cs, p, models.Kernel{Release: r.RunningKernel.Release, Version: r.Packages[fmt.Sprintf("linux-image-%s", r.RunningKernel.Release)].Version}) {
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
				v.CveContents[models.DebianSecurityTracker] = []models.CveContent{content.cveContent}
			}
			v.Confidences.AppendIfMissing(models.DebianSecurityTrackerMatch)
		} else {
			v = models.VulnInfo{
				CveID:       content.cveContent.CveID,
				CveContents: models.NewCveContents(content.cveContent),
				Confidences: models.Confidences{models.DebianSecurityTrackerMatch},
			}
		}

		for _, s := range content.fixStatuses {
			v.AffectedPackages = v.AffectedPackages.Store(s)
		}
		r.ScannedCves[content.cveContent.CveID] = v
	}

	return maps.Keys(detects), nil
}

func (deb Debian) isKernelSourcePackage(pkgname string) bool {
	switch ss := strings.Split(pkgname, "-"); len(ss) {
	case 1:
		return pkgname == "linux"
	case 2:
		if ss[0] != "liunx" {
			return false
		}
		switch ss[1] {
		case "grsec":
			return true
		default:
			_, err := strconv.ParseFloat(ss[1], 64)
			return err == nil
		}
	default:
		return false
	}
}

func (deb Debian) detect(cves map[string]gostmodels.DebianCVE, srcPkg models.SrcPackage, runningKernel models.Kernel) []cveContent {
	n := strings.NewReplacer("linux-signed", "linux", "linux-latest", "linux", "-amd64", "", "-arm64", "", "-i386", "").Replace(srcPkg.Name)

	var contents []cveContent
	for _, cve := range cves {
		c := cveContent{
			cveContent: *(Debian{}).ConvertToModel(&cve),
		}

		for _, p := range cve.Package {
			for _, r := range p.Release {
				switch r.Status {
				case "open", "undetermined":
					for _, bn := range srcPkg.BinaryNames {
						if deb.isKernelSourcePackage(n) && bn != fmt.Sprintf("linux-image-%s", runningKernel.Release) {
							continue
						}
						c.fixStatuses = append(c.fixStatuses, models.PackageFixStatus{
							Name:        bn,
							FixState:    r.Status,
							NotFixedYet: true,
						})
					}
				case "resolved":
					installedVersion := srcPkg.Version
					patchedVersion := r.FixedVersion

					if deb.isKernelSourcePackage(n) {
						installedVersion = runningKernel.Version
					}

					affected, err := deb.isGostDefAffected(installedVersion, patchedVersion)
					if err != nil {
						logging.Log.Debugf("Failed to parse versions: %s, Ver: %s, Gost: %s", err, installedVersion, patchedVersion)
						continue
					}

					if affected {
						for _, bn := range srcPkg.BinaryNames {
							if deb.isKernelSourcePackage(n) && bn != fmt.Sprintf("linux-image-%s", runningKernel.Release) {
								continue
							}
							c.fixStatuses = append(c.fixStatuses, models.PackageFixStatus{
								Name:    bn,
								FixedIn: patchedVersion,
							})
						}
					}
				default:
					logging.Log.Debugf("Failed to check vulnerable CVE. err: unknown status: %s", r.Status)
				}
			}
		}

		if len(c.fixStatuses) > 0 {
			contents = append(contents, c)
		}
	}
	return contents
}

func (deb Debian) isGostDefAffected(versionRelease, gostVersion string) (affected bool, err error) {
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
func (deb Debian) ConvertToModel(cve *gostmodels.DebianCVE) *models.CveContent {
	severity := ""
	for _, p := range cve.Package {
		for _, r := range p.Release {
			severity = r.Urgency
			break
		}
	}
	var optinal map[string]string
	if cve.Scope != "" {
		optinal = map[string]string{"attack range": cve.Scope}
	}
	return &models.CveContent{
		Type:          models.DebianSecurityTracker,
		CveID:         cve.CveID,
		Summary:       cve.Description,
		Cvss2Severity: severity,
		Cvss3Severity: severity,
		SourceLink:    fmt.Sprintf("https://security-tracker.debian.org/tracker/%s", cve.CveID),
		Optional:      optinal,
	}
}
