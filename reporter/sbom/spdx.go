package sbom

import (
	"fmt"
	"math/rand/v2"
	"time"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const (
	CreatorOrganization = "future-architect"
	CreatorTool         = "vuls"
)

const (
	DocumentSPDXIdentifier = "DOCUMENT"
	ElementOperatingSystem = "Operating-System"
	ElementPackage         = "Package"

	PackagePurposeOS          = "OPERATING-SYSTEM"
	PackagePurposeApplication = "APPLICATION"
	PackagePurposeLibrary     = "LIBRARY"

	PackageAnnotatorTool = "Tool"

	noneField = "NONE"

	RelationShipContains = common.TypeRelationshipContains
	RelationShipDepensOn = common.TypeRelationshipDependsOn
	RelationshipOther    = common.TypeRelationshipOther

	CategoryPackageManager = common.CategoryPackageManager
	PackageManagerPURL     = common.TypePackageManagerPURL

	CategorySecurity  = common.CategorySecurity
	SecurityCPE23Type = common.TypeSecurityCPE23Type
	SecurityAdvisory  = common.TypeSecurityAdvisory
)

func ToSPDX(r models.ScanResult) spdx.Document {
	root := osToSpdxPackage(r)
	// ScanedCves の map を作成する： Identifier -> CVE情報
	packageToURLMap := createPackageToURLMap(r)
	packages, relationships := spdxPackages(r, root, packageToURLMap)

	return spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    DocumentSPDXIdentifier,
		DocumentName:      root.PackageName,
		DocumentNamespace: fmt.Sprintf("%s-%s-%s", root.PackageName, root.PackageVersion, uuid.NewString()),
		CreationInfo:      spdxCreationInfo(r),
		Packages:          packages,
		Relationships:     relationships,
	}
}

func osToSpdxPackage(r models.ScanResult) *spdx.Package {
	family := constant.ServerTypePseudo
	if r.Family != "" {
		family = r.Family
	}

	var annotations []spdx.Annotation
	annotations = appendAnnotation(annotations, "OsFamily", r.Family, r.ReportedAt)
	if r.RunningKernel.Release != "" {
		annotations = appendAnnotation(annotations, "RunningKernelRelease", r.RunningKernel.Release, r.ReportedAt)
	}
	if r.RunningKernel.Version != "" {
		annotations = appendAnnotation(annotations, "RunningKernelVersion", r.RunningKernel.Version, r.ReportedAt)
	}

	return &spdx.Package{
		PackageSPDXIdentifier:     calculateSDPXIDentifier(ElementOperatingSystem),
		PackageName:               family,
		PackageVersion:            r.Release,
		PackageDownloadLocation:   noneField,
		Annotations:               annotations,
		PackageExternalReferences: []*spdx.PackageExternalReference{},
		PrimaryPackagePurpose:     PackagePurposeOS,
	}
}

func spdxCreationInfo(result models.ScanResult) *spdx.CreationInfo {
	toolName := CreatorTool
	if result.ReportedVersion != "" {
		toolName = fmt.Sprintf("%s-%s", CreatorTool, result.ReportedVersion)
	}

	ci := spdx.CreationInfo{
		Creators: []common.Creator{
			{Creator: CreatorOrganization, CreatorType: "Organization"},
			{Creator: toolName, CreatorType: "Tool"},
		},
		Created: result.ReportedAt.Format(time.RFC3339),
	}

	return &ci
}

func spdxPackages(result models.ScanResult, root *spdx.Package, packageToURLMap map[string][]string) ([]*spdx.Package, []*spdx.Relationship) {
	var packages []*spdx.Package
	var relationships []*spdx.Relationship

	// ospkgPackages
	if ospkgs := ospkgToSPDXPackages(result, packageToURLMap); len(ospkgs) > 0 {
		for _, pack := range ospkgs {
			packages = append(packages, &pack)
			relationships = append(relationships, makeSPDXRelationShip(root.PackageSPDXIdentifier, pack.PackageSPDXIdentifier, RelationShipContains))
		}
	}

	// cpePackages
	if cpePkgs := cpeToSPDXPackages(result, packageToURLMap); len(cpePkgs) > 0 {
		relationships = append(relationships, makeSPDXRelationShip(root.PackageSPDXIdentifier, cpePkgs[0].PackageSPDXIdentifier, RelationShipContains))
		for _, pack := range cpePkgs[1:] {
			packages = append(packages, &pack)
			relationships = append(relationships, makeSPDXRelationShip(cpePkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, RelationShipDepensOn))
		}
	}

	// libpkgPackages
	for _, libScanner := range result.LibraryScanners {
		if libpkgs := libpkgToSPDXPackages(libScanner, packageToURLMap, result.ReportedAt); len(libpkgs) > 0 {
			relationships = append(relationships, makeSPDXRelationShip(root.PackageSPDXIdentifier, libpkgs[0].PackageSPDXIdentifier, RelationShipContains))
			for _, pack := range libpkgs[1:] {
				packages = append(packages, &pack)
				relationships = append(relationships, makeSPDXRelationShip(libpkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, RelationShipDepensOn))
			}
		}
	}

	// ghpkgPackages
	for _, ghm := range result.GitHubManifests {
		if ghpkgs := ghpkgToSPDXPackages(ghm, packageToURLMap, result.ReportedAt); len(ghpkgs) > 0 {
			relationships = append(relationships, makeSPDXRelationShip(root.PackageSPDXIdentifier, ghpkgs[0].PackageSPDXIdentifier, RelationShipContains))
			for _, pack := range ghpkgs[1:] {
				packages = append(packages, &pack)
				relationships = append(relationships, makeSPDXRelationShip(ghpkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, RelationShipDepensOn))
			}
		}
	}

	// wppkgPackages
	if wppkgs := wppkgToSPDXPackages(result.WordPressPackages, packageToURLMap, result.ReportedAt); len(wppkgs) > 0 {
		relationships = append(relationships, makeSPDXRelationShip(root.PackageSPDXIdentifier, wppkgs[0].PackageSPDXIdentifier, RelationShipContains))
		for _, pack := range wppkgs[1:] {
			packages = append(packages, &pack)
			relationships = append(relationships, makeSPDXRelationShip(wppkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, RelationShipDepensOn))
		}
	}

	return packages, relationships
}

func ospkgToSPDXPackages(r models.ScanResult, packageToURLMap map[string][]string) []spdx.Package {
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

	packages := make([]spdx.Package, 0, len(r.Packages))
	for _, pack := range r.Packages {
		var annotations []spdx.Annotation
		if sp, ok := binToSrc[pack.Name]; ok {
			annotations = appendAnnotation(annotations, "SrcName", sp.name, r.ReportedAt)
			annotations = appendAnnotation(annotations, "SrcVersion", sp.version, r.ReportedAt)
			annotations = appendAnnotation(annotations, "SrcArch", sp.arch, r.ReportedAt)
		}

		var externalRefs []*spdx.PackageExternalReference
		purl := osPkgToPURL(r.Family, r.Release, pack)
		externalRefs = appendExternalRefs(externalRefs, CategoryPackageManager, PackageManagerPURL, purl.String())

		if urls, exists := packageToURLMap[pack.Name]; exists {
			for _, url := range urls {
				externalRefs = appendExternalRefs(externalRefs, CategorySecurity, SecurityAdvisory, url)
			}
		}

		spdxPackage := spdx.Package{
			PackageSPDXIdentifier:     calculateSDPXIDentifier(ElementPackage),
			PackageName:               pack.Name,
			PackageVersion:            pack.Version,
			PackageDownloadLocation:   noneField,
			Annotations:               annotations,
			PackageExternalReferences: externalRefs,
		}
		packages = append(packages, spdxPackage)
	}
	return packages
}

func cpeToSPDXPackages(r models.ScanResult, packageToURLMap map[string][]string) []spdx.Package {
	cpes := map[string]struct{}{}
	for _, cve := range r.ScannedCves {
		for _, cpe := range cve.CpeURIs {
			cpes[cpe] = struct{}{}
		}
	}

	if len(cpes) == 0 {
		return nil
	}

	packages := make([]spdx.Package, 0, 1+len(cpes))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier: calculateSDPXIDentifier(ElementPackage),
		PackageName:           "CPEs",
		Annotations:           appendAnnotation(nil, "Type", "CPE", r.ReportedAt),
		PrimaryPackagePurpose: PackagePurposeApplication,
	})

	for cpe := range cpes {
		var externalRefs []*spdx.PackageExternalReference
		externalRefs = appendExternalRefs(externalRefs, CategorySecurity, SecurityCPE23Type, cpe)

		if urls, exists := packageToURLMap[cpe]; exists {
			for _, url := range urls {
				externalRefs = appendExternalRefs(externalRefs, CategorySecurity, SecurityAdvisory, url)
			}
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     calculateSDPXIDentifier(ElementPackage),
			PackageName:               cpe,
			PackageExternalReferences: externalRefs,
		})
	}

	return packages
}

func libpkgToSPDXPackages(libScanner models.LibraryScanner, packageToURLMap map[string][]string, reportedAt time.Time) []spdx.Package {
	if len(libScanner.Libs) == 0 {
		return nil
	}

	packages := make([]spdx.Package, 0, 1+len(libScanner.Libs))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier: calculateSDPXIDentifier(ElementPackage),
		PackageName:           libScanner.LockfilePath,
		Annotations:           appendAnnotation(nil, "Type", string(libScanner.Type), reportedAt),
		PrimaryPackagePurpose: PackagePurposeApplication,
	})

	for _, lib := range libScanner.Libs {
		var externalRefs []*spdx.PackageExternalReference
		purl := libPkgToPURL(libScanner, lib)
		externalRefs = appendExternalRefs(externalRefs, CategoryPackageManager, PackageManagerPURL, purl.String())

		libkey := fmt.Sprintf("lib:%s:%s", libScanner.LockfilePath, lib.Name)
		if urls, exists := packageToURLMap[libkey]; exists {
			for _, url := range urls {
				externalRefs = appendExternalRefs(externalRefs, CategorySecurity, SecurityAdvisory, url)
			}
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier: calculateSDPXIDentifier(ElementPackage),
			PackageName:           lib.Name,
			PackageVersion:        lib.Version,
		})
	}

	return packages
}

func ghpkgToSPDXPackages(ghm models.DependencyGraphManifest, packageToURLMap map[string][]string, reportedAt time.Time) []spdx.Package {
	if len(ghm.Dependencies) == 0 {
		return nil
	}

	packages := make([]spdx.Package, 0, 1+len(ghm.Dependencies))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier: calculateSDPXIDentifier(ElementPackage),
		PackageName:           ghm.BlobPath,
		Annotations:           appendAnnotation(nil, "Type", string(ghm.Ecosystem()), reportedAt),
		PrimaryPackagePurpose: PackagePurposeApplication,
	})

	for _, dep := range ghm.Dependencies {
		var externalRefs []*spdx.PackageExternalReference
		purl := ghPkgToPURL(ghm, dep)
		externalRefs = appendExternalRefs(externalRefs, CategoryPackageManager, PackageManagerPURL, purl.String())

		ghkey := fmt.Sprintf("gh:%s:%s", ghm.RepoURLFilename(), dep.PackageName)
		if urls, exists := packageToURLMap[ghkey]; exists {
			for _, url := range urls {
				externalRefs = appendExternalRefs(externalRefs, CategorySecurity, SecurityAdvisory, url)
			}
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     calculateSDPXIDentifier(ElementPackage),
			PackageName:               dep.PackageName,
			PackageVersion:            dep.Version(),
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     PackagePurposeLibrary,
		})
	}

	return packages
}

func wppkgToSPDXPackages(wppkgs models.WordPressPackages, packageToURLMap map[string][]string, reportedAt time.Time) []spdx.Package {
	if len(wppkgs) == 0 {
		return nil
	}

	packages := make([]spdx.Package, 0, 1+len(wppkgs))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier: calculateSDPXIDentifier(ElementPackage),
		PackageName:           "wordPress",
		Annotations:           appendAnnotation(nil, "Type", "WordPress", reportedAt),
		PrimaryPackagePurpose: PackagePurposeApplication,
	})

	for _, wppkg := range wppkgs {
		var externalRefs []*spdx.PackageExternalReference
		purl := wpPkgToPURL(wppkg)
		externalRefs = appendExternalRefs(externalRefs, CategoryPackageManager, PackageManagerPURL, purl.String())

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     calculateSDPXIDentifier(ElementPackage),
			PackageName:               wppkg.Name,
			PackageVersion:            wppkg.Version,
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     PackagePurposeLibrary,
		})
	}

	return packages
}

func appendAnnotation(annotations []spdx.Annotation, key, value string, reportedAt time.Time) []spdx.Annotation {
	if value == "" {
		return annotations
	}
	return append(annotations, spdx.Annotation{
		Annotator: spdx.Annotator{
			Annotator:     fmt.Sprintf("%s:%s", CreatorOrganization, CreatorTool),
			AnnotatorType: PackageAnnotatorTool,
		},
		AnnotationDate:    reportedAt.Format(time.RFC3339),
		AnnotationType:    spdx.CategoryOther,
		AnnotationComment: fmt.Sprintf("%s: %s", key, value),
	})
}

func appendExternalRefs(extRefs []*spdx.PackageExternalReference, category, refType, locator string) []*spdx.PackageExternalReference {
	if locator == "" {
		return extRefs
	}

	return append(extRefs, &spdx.PackageExternalReference{
		Category: category,
		RefType:  refType,
		Locator:  locator,
	})
}

func makeSPDXRelationShip(refA, refB spdx.ElementID, relationship string) *spdx.Relationship {
	return &spdx.Relationship{
		RefA:         common.MakeDocElementID("", string(refA)),
		RefB:         common.MakeDocElementID("", string(refB)),
		Relationship: relationship,
	}
}

// createPackageToURLMap builds a flattened mapping from package identifiers to
// lists of vulnerability reference URLs aggregated from all CVEs in the scan result.
//
// Key formats:
//
//	OS        : <name>
//	CPE       : <cpe-uri>
//	Lib       : lib:<path>:<name>
//	GitHub    : gh:<manifestPath>:<packageName>
//	WordPress : wp:<name>
func createPackageToURLMap(r models.ScanResult) map[string][]string {
	result := make(map[string][]string)

	for _, cve := range r.ScannedCves {
		cveURLSet := make(map[string]struct{})
		for _, contents := range cve.CveContents {
			for _, c := range contents {
				if c.SourceLink != "" {
					cveURLSet[c.SourceLink] = struct{}{}
				}
				for _, ref := range c.References {
					if ref.Link != "" {
						cveURLSet[ref.Link] = struct{}{}
					}
				}
			}
		}
		if len(cveURLSet) == 0 {
			continue
		}

		cveURLs := make([]string, 0, len(cveURLSet))
		for u := range cveURLSet {
			cveURLs = append(cveURLs, u)
		}

		var keys []string
		for _, p := range cve.AffectedPackages {
			if p.Name != "" {
				keys = append(keys, p.Name)
			}
		}
		for _, cpe := range cve.CpeURIs {
			if cpe != "" {
				keys = append(keys, cpe)
			}
		}
		for _, lf := range cve.LibraryFixedIns {
			if lf.Path != "" && lf.Name != "" {
				keys = append(keys, fmt.Sprintf("lib:%s:%s", lf.Path, lf.Name))
			}
		}
		for _, alert := range cve.GitHubSecurityAlerts {
			if alert.RepoURLManifestPath() != "" && alert.Package.Name != "" {
				keys = append(keys, fmt.Sprintf("gh:%s:%s", alert.RepoURLManifestPath(), alert.Package.Name))
			}
		}
		for _, wp := range cve.WpPackageFixStats {
			if wp.Name != "" {
				keys = append(keys, fmt.Sprintf("wp:%s", wp.Name))
			}
		}

		for _, k := range keys {
			result[k] = append(result[k], cveURLs...)
		}
	}

	return result
}

func calculateSDPXIDentifier(packageType string) spdx.ElementID {
	return spdx.ElementID(fmt.Sprintf("%s-%016x", packageType, rand.Uint64()))
}
