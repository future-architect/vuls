package sbom

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func GenerateCycloneDX(format cdx.BOMFileFormat, r models.ScanResult) ([]byte, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = uuid.New().URN()
	bom.Metadata = cdxMetadata(r)
	bom.Components, bom.Dependencies, bom.Vulnerabilities = cdxComponents(r, bom.Metadata.Component.BOMRef)

	buf := new(bytes.Buffer)
	enc := cdx.NewBOMEncoder(buf, format)
	enc.SetPretty(true)
	if err := enc.Encode(bom); err != nil {
		return nil, xerrors.Errorf("Failed to encode CycloneDX. err: %w", err)
	}
	return buf.Bytes(), nil
}

func cdxMetadata(result models.ScanResult) *cdx.Metadata {
	metadata := cdx.Metadata{
		Timestamp: result.ReportedAt.Format(time.RFC3339),
		Tools: &[]cdx.Tool{
			{
				Vendor:  "future-architect",
				Name:    "vuls",
				Version: fmt.Sprintf("%s-%s", result.ReportedVersion, result.ReportedRevision),
			},
		},
		Component: &cdx.Component{
			BOMRef: uuid.NewString(),
			Type:   cdx.ComponentTypeOS,
			Name:   result.ServerName,
		},
	}
	return &metadata
}

func cdxComponents(result models.ScanResult, metaBomRef string) (*[]cdx.Component, *[]cdx.Dependency, *[]cdx.Vulnerability) {
	var components []cdx.Component
	bomRefs := map[string][]string{}

	ospkgToPURL := map[string]string{}
	if ospkgComps := ospkgToCdxComponents(result.Family, result.Release, result.RunningKernel, result.Packages, result.SrcPackages, ospkgToPURL); ospkgComps != nil {
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], ospkgComps[0].BOMRef)
		for _, comp := range ospkgComps[1:] {
			bomRefs[ospkgComps[0].BOMRef] = append(bomRefs[ospkgComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, ospkgComps...)
	}

	if cpeComps := cpeToCdxComponents(result.ScannedCves); cpeComps != nil {
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], cpeComps[0].BOMRef)
		for _, comp := range cpeComps[1:] {
			bomRefs[cpeComps[0].BOMRef] = append(bomRefs[cpeComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, cpeComps...)
	}

	libpkgToPURL := map[string]map[string]string{}
	for _, libscanner := range result.LibraryScanners {
		libpkgToPURL[libscanner.LockfilePath] = map[string]string{}

		libpkgComps := libpkgToCdxComponents(libscanner, libpkgToPURL)
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], libpkgComps[0].BOMRef)
		for _, comp := range libpkgComps[1:] {
			bomRefs[libpkgComps[0].BOMRef] = append(bomRefs[libpkgComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, libpkgComps...)
	}

	ghpkgToPURL := map[string]map[string]string{}
	for _, ghm := range result.GitHubManifests {
		ghpkgToPURL[ghm.Filename] = map[string]string{}

		ghpkgComps := ghpkgToCdxComponents(ghm, ghpkgToPURL)
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], ghpkgComps[0].BOMRef)
		for _, comp := range ghpkgComps[1:] {
			bomRefs[ghpkgComps[0].BOMRef] = append(bomRefs[ghpkgComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, ghpkgComps...)
	}

	wppkgToPURL := map[string]string{}
	if wppkgComps := wppkgToCdxComponents(result.WordPressPackages, wppkgToPURL); wppkgComps != nil {
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], wppkgComps[0].BOMRef)
		for _, comp := range wppkgComps[1:] {
			bomRefs[wppkgComps[0].BOMRef] = append(bomRefs[wppkgComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, wppkgComps...)
	}

	return &components, cdxDependencies(bomRefs), cdxVulnerabilities(result, ospkgToPURL, libpkgToPURL, ghpkgToPURL, wppkgToPURL)
}

func osToCdxComponent(family, release, runningKernelRelease, runningKernelVersion string) cdx.Component {
	props := []cdx.Property{
		{
			Name:  "future-architect:vuls:Type",
			Value: "Package",
		},
	}
	if runningKernelRelease != "" {
		props = append(props, cdx.Property{
			Name:  "RunningKernelRelease",
			Value: runningKernelRelease,
		})
	}
	if runningKernelVersion != "" {
		props = append(props, cdx.Property{
			Name:  "RunningKernelVersion",
			Value: runningKernelVersion,
		})
	}
	return cdx.Component{
		BOMRef:     uuid.NewString(),
		Type:       cdx.ComponentTypeOS,
		Name:       family,
		Version:    release,
		Properties: &props,
	}
}

func ospkgToCdxComponents(family, release string, runningKernel models.Kernel, binpkgs models.Packages, srcpkgs models.SrcPackages, ospkgToPURL map[string]string) []cdx.Component {
	if family == "" {
		return nil
	}

	components := []cdx.Component{
		osToCdxComponent(family, release, runningKernel.Release, runningKernel.Version),
	}

	if len(binpkgs) == 0 {
		return components
	}

	type srcpkg struct {
		name    string
		version string
		arch    string
	}
	binToSrc := map[string]srcpkg{}
	for _, pack := range srcpkgs {
		for _, binpkg := range pack.BinaryNames {
			binToSrc[binpkg] = srcpkg{
				name:    pack.Name,
				version: pack.Version,
				arch:    pack.Arch,
			}
		}
	}

	for _, pack := range binpkgs {
		var props []cdx.Property
		if p, ok := binToSrc[pack.Name]; ok {
			if p.name != "" {
				props = append(props, cdx.Property{
					Name:  "future-architect:vuls:SrcName",
					Value: p.name,
				})
			}
			if p.version != "" {
				props = append(props, cdx.Property{
					Name:  "future-architect:vuls:SrcVersion",
					Value: p.version,
				})
			}
			if p.arch != "" {
				props = append(props, cdx.Property{
					Name:  "future-architect:vuls:SrcArch",
					Value: p.arch,
				})
			}
		}

		purl := toPkgPURL(family, release, pack.Name, pack.Version, pack.Release, pack.Arch, pack.Repository)
		components = append(components, cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       pack.Name,
			Version:    pack.Version,
			PackageURL: purl,
			Properties: &props,
		})

		ospkgToPURL[pack.Name] = purl
	}
	return components
}

func cpeToCdxComponents(scannedCves models.VulnInfos) []cdx.Component {
	cpes := map[string]struct{}{}
	for _, cve := range scannedCves {
		for _, cpe := range cve.CpeURIs {
			cpes[cpe] = struct{}{}
		}
	}
	if len(cpes) == 0 {
		return nil
	}

	components := []cdx.Component{
		{
			BOMRef: uuid.NewString(),
			Type:   cdx.ComponentTypeApplication,
			Name:   "CPEs",
			Properties: &[]cdx.Property{
				{
					Name:  "future-architect:vuls:Type",
					Value: "CPE",
				},
			},
		},
	}
	for cpe := range cpes {
		components = append(components, cdx.Component{
			BOMRef: cpe,
			Type:   cdx.ComponentTypeLibrary,
			Name:   cpe,
			CPE:    cpe,
		})
	}

	return components
}

func libpkgToCdxComponents(libscanner models.LibraryScanner, libpkgToPURL map[string]map[string]string) []cdx.Component {
	components := []cdx.Component{
		{
			BOMRef: uuid.NewString(),
			Type:   cdx.ComponentTypeApplication,
			Name:   libscanner.LockfilePath,
			Properties: &[]cdx.Property{
				{
					Name:  "future-architect:vuls:Type",
					Value: libscanner.Type,
				},
			},
		},
	}

	for _, lib := range libscanner.Libs {
		purl := packageurl.NewPackageURL(libscanner.Type, "", lib.Name, lib.Version, packageurl.Qualifiers{{Key: "file_path", Value: libscanner.LockfilePath}}, "").ToString()
		components = append(components, cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       lib.Name,
			Version:    lib.Version,
			PackageURL: purl,
		})

		libpkgToPURL[libscanner.LockfilePath][lib.Name] = purl
	}

	return components
}

func ghpkgToCdxComponents(m models.DependencyGraphManifest, ghpkgToPURL map[string]map[string]string) []cdx.Component {
	components := []cdx.Component{
		{
			BOMRef: uuid.NewString(),
			Type:   cdx.ComponentTypeApplication,
			Name:   m.Filename,
			Properties: &[]cdx.Property{
				{
					Name:  "future-architect:vuls:Type",
					Value: m.Ecosystem(),
				},
			},
		},
	}

	for _, dep := range m.Dependencies {
		purl := packageurl.NewPackageURL(m.Ecosystem(), "", dep.PackageName, dep.Version(), packageurl.Qualifiers{{Key: "file_path", Value: m.Filename}}, "").ToString()
		components = append(components, cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       dep.PackageName,
			Version:    dep.Version(),
			PackageURL: purl,
		})

		ghpkgToPURL[m.Filename][dep.PackageName] = purl
	}

	return components
}

func wppkgToCdxComponents(wppkgs models.WordPressPackages, wppkgToPURL map[string]string) []cdx.Component {
	if len(wppkgs) == 0 {
		return nil
	}

	components := []cdx.Component{
		{
			BOMRef: uuid.NewString(),
			Type:   cdx.ComponentTypeApplication,
			Name:   "wordpress",
			Properties: &[]cdx.Property{
				{
					Name:  "future-architect:vuls:Type",
					Value: "WordPress",
				},
			},
		},
	}

	for _, wppkg := range wppkgs {
		purl := packageurl.NewPackageURL("wordpress", wppkg.Type, wppkg.Name, wppkg.Version, packageurl.Qualifiers{{Key: "status", Value: wppkg.Status}}, "").ToString()
		components = append(components, cdx.Component{
			BOMRef:     purl,
			Type:       cdx.ComponentTypeLibrary,
			Name:       wppkg.Name,
			Version:    wppkg.Version,
			PackageURL: purl,
		})

		wppkgToPURL[wppkg.Name] = purl
	}

	return components
}

func cdxDependencies(bomRefs map[string][]string) *[]cdx.Dependency {
	dependencies := make([]cdx.Dependency, 0, len(bomRefs))
	for ref, depRefs := range bomRefs {
		ds := depRefs
		dependencies = append(dependencies, cdx.Dependency{
			Ref:          ref,
			Dependencies: &ds,
		})
	}
	return &dependencies
}

func toPkgPURL(osFamily, osVersion, packName, packVersion, packRelease, packArch, packRepository string) string {
	var purlType string
	switch osFamily {
	case constant.Alma, constant.Amazon, constant.CentOS, constant.Fedora, constant.OpenSUSE, constant.OpenSUSELeap, constant.Oracle, constant.RedHat, constant.Rocky, constant.SUSEEnterpriseDesktop, constant.SUSEEnterpriseServer:
		purlType = "rpm"
	case constant.Alpine:
		purlType = "apk"
	case constant.Debian, constant.Raspbian, constant.Ubuntu:
		purlType = "deb"
	case constant.FreeBSD:
		purlType = "pkg"
	case constant.Windows:
		purlType = "win"
	case constant.ServerTypePseudo:
		purlType = "pseudo"
	default:
		purlType = "unknown"
	}

	version := packVersion
	if packRelease != "" {
		version = fmt.Sprintf("%s-%s", packVersion, packRelease)
	}

	var qualifiers packageurl.Qualifiers
	if osVersion != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "distro",
			Value: osVersion,
		})
	}
	if packArch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: packArch,
		})
	}
	if packRepository != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repo",
			Value: packRepository,
		})
	}

	return packageurl.NewPackageURL(purlType, osFamily, packName, version, qualifiers, "").ToString()
}

func cdxVulnerabilities(result models.ScanResult, ospkgToPURL map[string]string, libpkgToPURL, ghpkgToPURL map[string]map[string]string, wppkgToPURL map[string]string) *[]cdx.Vulnerability {
	vulnerabilities := make([]cdx.Vulnerability, 0, len(result.ScannedCves))
	for _, cve := range result.ScannedCves {
		vulnerabilities = append(vulnerabilities, cdx.Vulnerability{
			ID:          cve.CveID,
			Ratings:     cdxRatings(cve.CveContents),
			CWEs:        cdxCWEs(cve.CveContents),
			Description: cdxDescription(cve.CveContents),
			Advisories:  cdxAdvisories(cve.CveContents),
			Affects:     cdxAffects(cve, ospkgToPURL, libpkgToPURL, ghpkgToPURL, wppkgToPURL),
		})
	}
	return &vulnerabilities
}

func cdxRatings(cveContents models.CveContents) *[]cdx.VulnerabilityRating {
	var ratings []cdx.VulnerabilityRating
	for _, contents := range cveContents {
		for _, content := range contents {
			if content.Cvss2Score != 0 || content.Cvss2Vector != "" || content.Cvss2Severity != "" {
				ratings = append(ratings, cdxCVSS2Rating(string(content.Type), content.Cvss2Vector, content.Cvss2Score, content.Cvss2Severity))
			}
			if content.Cvss3Score != 0 || content.Cvss3Vector != "" || content.Cvss3Severity != "" {
				ratings = append(ratings, cdxCVSS3Rating(string(content.Type), content.Cvss3Vector, content.Cvss3Score, content.Cvss3Severity))
			}
		}
	}
	return &ratings
}

func cdxCVSS2Rating(source, vector string, score float64, severity string) cdx.VulnerabilityRating {
	r := cdx.VulnerabilityRating{
		Source: &cdx.Source{Name: source},
		Method: cdx.ScoringMethodCVSSv2,
		Vector: vector,
	}
	if score != 0 {
		r.Score = &score
	}
	switch strings.ToLower(severity) {
	case "high":
		r.Severity = cdx.SeverityHigh
	case "medium":
		r.Severity = cdx.SeverityMedium
	case "low":
		r.Severity = cdx.SeverityLow
	default:
		r.Severity = cdx.SeverityUnknown
	}
	return r
}

func cdxCVSS3Rating(source, vector string, score float64, severity string) cdx.VulnerabilityRating {
	r := cdx.VulnerabilityRating{
		Source: &cdx.Source{Name: source},
		Method: cdx.ScoringMethodCVSSv3,
		Vector: vector,
	}
	if strings.HasPrefix(vector, "CVSS:3.1") {
		r.Method = cdx.ScoringMethodCVSSv31
	}
	if score != 0 {
		r.Score = &score
	}
	switch strings.ToLower(severity) {
	case "critical":
		r.Severity = cdx.SeverityCritical
	case "high":
		r.Severity = cdx.SeverityHigh
	case "medium":
		r.Severity = cdx.SeverityMedium
	case "low":
		r.Severity = cdx.SeverityLow
	case "none":
		r.Severity = cdx.SeverityNone
	default:
		r.Severity = cdx.SeverityUnknown
	}
	return r
}

func cdxAffects(cve models.VulnInfo, ospkgToPURL map[string]string, libpkgToPURL, ghpkgToPURL map[string]map[string]string, wppkgToPURL map[string]string) *[]cdx.Affects {
	affects := make([]cdx.Affects, 0, len(cve.AffectedPackages)+len(cve.CpeURIs)+len(cve.LibraryFixedIns)+len(cve.WpPackageFixStats))

	for _, p := range cve.AffectedPackages {
		affects = append(affects, cdx.Affects{
			Ref: ospkgToPURL[p.Name],
		})
	}
	for _, cpe := range cve.CpeURIs {
		affects = append(affects, cdx.Affects{
			Ref: cpe,
		})
	}
	for _, lib := range cve.LibraryFixedIns {
		affects = append(affects, cdx.Affects{
			Ref: libpkgToPURL[lib.Path][lib.Name],
		})
	}
	for _, alert := range cve.GitHubSecurityAlerts {
		// TODO: not in dependency graph
		if purl, ok := ghpkgToPURL[alert.Package.ManifestPath][alert.Package.Name]; ok {
			affects = append(affects, cdx.Affects{
				Ref: purl,
			})
		}
	}
	for _, wppack := range cve.WpPackageFixStats {
		affects = append(affects, cdx.Affects{
			Ref: wppkgToPURL[wppack.Name],
		})
	}

	return &affects
}

func cdxCWEs(cveContents models.CveContents) *[]int {
	m := map[int]struct{}{}
	for _, contents := range cveContents {
		for _, content := range contents {
			for _, cweID := range content.CweIDs {
				if !strings.HasPrefix(cweID, "CWE-") {
					continue
				}
				i, err := strconv.Atoi(strings.TrimPrefix(cweID, "CWE-"))
				if err != nil {
					continue
				}
				m[i] = struct{}{}
			}
		}
	}
	cweIDs := maps.Keys(m)
	return &cweIDs
}

func cdxDescription(cveContents models.CveContents) string {
	if contents, ok := cveContents[models.Nvd]; ok {
		return contents[0].Summary
	}
	return ""
}

func cdxAdvisories(cveContents models.CveContents) *[]cdx.Advisory {
	urls := map[string]struct{}{}
	for _, contents := range cveContents {
		for _, content := range contents {
			if content.SourceLink != "" {
				urls[content.SourceLink] = struct{}{}
			}
			for _, r := range content.References {
				urls[r.Link] = struct{}{}
			}
		}
	}
	advisories := make([]cdx.Advisory, 0, len(urls))
	for u := range urls {
		advisories = append(advisories, cdx.Advisory{
			URL: u,
		})
	}
	return &advisories
}
