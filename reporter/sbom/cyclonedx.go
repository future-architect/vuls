package sbom

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

// ToCycloneDX converts a ScanResult to a CycloneDX BOM.
func ToCycloneDX(r models.ScanResult) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.SerialNumber = uuid.New().URN()
	bom.Metadata = cdxMetadata(r)
	bom.Components, bom.Dependencies, bom.Vulnerabilities = cdxComponents(r, bom.Metadata.Component.BOMRef)
	return bom
}

// SerializeCycloneDX serializes a CycloneDX BOM to a byte array.
func SerializeCycloneDX(bom *cdx.BOM, format cdx.BOMFileFormat) ([]byte, error) {
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
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{
				{
					Type:    cdx.ComponentTypeApplication,
					Group:   "future-architect",
					Name:    "vuls",
					Version: fmt.Sprintf("%s-%s", result.ReportedVersion, result.ReportedRevision),
				},
			},
		},
		Component: osToCdxComponent(result),
	}
	return &metadata
}

func cdxComponents(result models.ScanResult, metaBomRef string) (*[]cdx.Component, *[]cdx.Dependency, *[]cdx.Vulnerability) {
	var components []cdx.Component
	bomRefs := map[string][]string{}

	ospkgToPURL := map[string]string{}
	if ospkgComps := ospkgToCdxComponents(result, ospkgToPURL); len(ospkgComps) > 0 {
		for _, comp := range ospkgComps {
			bomRefs[metaBomRef] = append(bomRefs[metaBomRef], comp.BOMRef)
		}
		components = append(components, ospkgComps...)
	}

	if cpeComps := cpeToCdxComponents(result.ScannedCves); len(cpeComps) > 0 {
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], cpeComps[0].BOMRef)
		for _, comp := range cpeComps[1:] {
			bomRefs[cpeComps[0].BOMRef] = append(bomRefs[cpeComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, cpeComps...)
	}

	libpkgToPURL := map[string]map[string]string{}
	for _, libscanner := range result.LibraryScanners {
		libpkgToPURL[libscanner.LockfilePath] = map[string]string{}

		if libpkgComps := libpkgToCdxComponents(libscanner, libpkgToPURL); len(libpkgComps) > 0 {
			bomRefs[metaBomRef] = append(bomRefs[metaBomRef], libpkgComps[0].BOMRef)
			for _, comp := range libpkgComps[1:] {
				bomRefs[libpkgComps[0].BOMRef] = append(bomRefs[libpkgComps[0].BOMRef], comp.BOMRef)
			}
			components = append(components, libpkgComps...)
		}
	}

	ghpkgToPURL := map[string]map[string]string{}
	for _, ghm := range result.GitHubManifests {
		ghpkgToPURL[ghm.RepoURLFilename()] = map[string]string{}

		if ghpkgComps := ghpkgToCdxComponents(ghm, ghpkgToPURL); len(ghpkgComps) > 0 {
			bomRefs[metaBomRef] = append(bomRefs[metaBomRef], ghpkgComps[0].BOMRef)
			for _, comp := range ghpkgComps[1:] {
				bomRefs[ghpkgComps[0].BOMRef] = append(bomRefs[ghpkgComps[0].BOMRef], comp.BOMRef)
			}
			components = append(components, ghpkgComps...)
		}
	}

	wppkgToPURL := map[string]string{}
	if wppkgComps := wppkgToCdxComponents(result.WordPressPackages, wppkgToPURL); len(wppkgComps) > 0 {
		bomRefs[metaBomRef] = append(bomRefs[metaBomRef], wppkgComps[0].BOMRef)
		for _, comp := range wppkgComps[1:] {
			bomRefs[wppkgComps[0].BOMRef] = append(bomRefs[wppkgComps[0].BOMRef], comp.BOMRef)
		}
		components = append(components, wppkgComps...)
	}

	return &components, cdxDependencies(bomRefs), cdxVulnerabilities(result, ospkgToPURL, libpkgToPURL, ghpkgToPURL, wppkgToPURL)
}

func osToCdxComponent(r models.ScanResult) *cdx.Component {
	family := constant.ServerTypePseudo
	if r.Family != "" {
		family = r.Family
	}

	props := []cdx.Property{
		{
			Name:  "future-architect:vuls:Type",
			Value: family,
		},
	}
	if r.RunningKernel.Release != "" {
		props = append(props, cdx.Property{
			Name:  "RunningKernelRelease",
			Value: r.RunningKernel.Release,
		})
	}
	if r.RunningKernel.Version != "" {
		props = append(props, cdx.Property{
			Name:  "RunningKernelVersion",
			Value: r.RunningKernel.Version,
		})
	}
	return &cdx.Component{
		BOMRef:     uuid.NewString(),
		Type:       cdx.ComponentTypeOS,
		Name:       family,
		Version:    r.Release,
		Properties: &props,
	}
}

func ospkgToCdxComponents(r models.ScanResult, ospkgToPURL map[string]string) []cdx.Component {
	if r.Family == "" || len(r.Packages) == 0 {
		return nil
	}

	type srcpkg struct {
		name    string
		version string
		arch    string
	}
	binToSrc := map[string]srcpkg{}
	for _, pack := range r.SrcPackages {
		for _, binpkg := range pack.BinaryNames {
			binToSrc[binpkg] = srcpkg{
				name:    pack.Name,
				version: pack.Version,
				arch:    pack.Arch,
			}
		}
	}

	components := make([]cdx.Component, 0, len(r.Packages))
	for _, pack := range r.Packages {
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

		purl := osPkgToPURL(r.Family, r.Release, pack.Name, pack.Version, pack.Release, pack.Arch, pack.Repository)
		components = append(components, cdx.Component{
			BOMRef:     purl.ToString(),
			Type:       cdx.ComponentTypeLibrary,
			Name:       pack.Name,
			Version:    pack.Version,
			PackageURL: purl.ToString(),
			Properties: &props,
		})

		ospkgToPURL[pack.Name] = purl.ToString()
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

	components := make([]cdx.Component, 0, 1+len(cpes))

	components = append(components, cdx.Component{
		BOMRef: uuid.NewString(),
		Type:   cdx.ComponentTypeApplication,
		Name:   "CPEs",
		Properties: &[]cdx.Property{
			{
				Name:  "future-architect:vuls:Type",
				Value: "CPE",
			},
		},
	})
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
	if len(libpkgToPURL) == 0 {
		return nil
	}

	components := make([]cdx.Component, 0, 1+len(libscanner.Libs))

	components = append(components, cdx.Component{
		BOMRef: uuid.NewString(),
		Type:   cdx.ComponentTypeApplication,
		Name:   libscanner.LockfilePath,
		Properties: &[]cdx.Property{
			{
				Name:  "future-architect:vuls:Type",
				Value: string(libscanner.Type),
			},
		},
	})
	for _, lib := range libscanner.Libs {
		purl := libPkgToPURL(libscanner, lib)
		components = append(components, cdx.Component{
			BOMRef:     purl.ToString(),
			Type:       cdx.ComponentTypeLibrary,
			Name:       lib.Name,
			Version:    lib.Version,
			PackageURL: purl.ToString(),
		})

		libpkgToPURL[libscanner.LockfilePath][lib.Name] = purl.ToString()
	}

	return components
}

func ghpkgToCdxComponents(m models.DependencyGraphManifest, ghpkgToPURL map[string]map[string]string) []cdx.Component {
	if len(m.Dependencies) == 0 {
		return nil
	}

	components := make([]cdx.Component, 0, 1+len(m.Dependencies))

	components = append(components, cdx.Component{
		BOMRef: uuid.NewString(),
		Type:   cdx.ComponentTypeApplication,
		Name:   m.BlobPath,
		Properties: &[]cdx.Property{
			{
				Name:  "future-architect:vuls:Type",
				Value: m.Ecosystem(),
			},
		},
	})
	for _, dep := range m.Dependencies {
		purl := ghPkgToPURL(m, dep)
		components = append(components, cdx.Component{
			BOMRef:     purl.ToString(),
			Type:       cdx.ComponentTypeLibrary,
			Name:       dep.PackageName,
			Version:    dep.Version(),
			PackageURL: purl.ToString(),
		})

		ghpkgToPURL[m.RepoURLFilename()][dep.PackageName] = purl.ToString()
	}

	return components
}

func wppkgToCdxComponents(wppkgs models.WordPressPackages, wppkgToPURL map[string]string) []cdx.Component {
	if len(wppkgs) == 0 {
		return nil
	}

	components := make([]cdx.Component, 0, 1+len(wppkgs))

	components = append(components, cdx.Component{
		BOMRef: uuid.NewString(),
		Type:   cdx.ComponentTypeApplication,
		Name:   "wordpress",
		Properties: &[]cdx.Property{
			{
				Name:  "future-architect:vuls:Type",
				Value: "WordPress",
			},
		},
	})
	for _, wppkg := range wppkgs {
		purl := wpPkgToPURL(wppkg)
		components = append(components, cdx.Component{
			BOMRef:     purl.ToString(),
			Type:       cdx.ComponentTypeLibrary,
			Name:       wppkg.Name,
			Version:    wppkg.Version,
			PackageURL: purl.ToString(),
		})

		wppkgToPURL[wppkg.Name] = purl.ToString()
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
			if content.Cvss40Score != 0 || content.Cvss40Vector != "" || content.Cvss40Severity != "" {
				ratings = append(ratings, cdxCVSS40Rating(string(content.Type), content.Cvss40Vector, content.Cvss40Score, content.Cvss40Severity))
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

func cdxCVSS40Rating(source, vector string, score float64, severity string) cdx.VulnerabilityRating {
	r := cdx.VulnerabilityRating{
		Source: &cdx.Source{Name: source},
		Method: cdx.ScoringMethodCVSSv4,
		Vector: vector,
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
		if purl, ok := ghpkgToPURL[alert.RepoURLManifestPath()][alert.Package.Name]; ok {
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
	cweIDs := slices.Collect(maps.Keys(m))
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
