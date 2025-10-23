package sbom

import (
	"cmp"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

const (
	creatorOrganization = "future-architect"
	creatorTool         = "vuls"
	documentNamespace   = "https://www.future.co.jp/spdxdoc"

	documentSPDXIdentifier = "DOCUMENT"
	elementOperatingSystem = "Operating-System"
	elementPackage         = "Package"

	packagePurposeOS          = "OPERATING-SYSTEM"
	packagePurposeApplication = "APPLICATION"
	packagePurposeLibrary     = "LIBRARY"

	packageAnnotatorTool = "Tool"
	annotationOther      = "Other"

	valueNone = "NONE"

	relationshipDescribe = common.TypeRelationshipDescribe
	relationshipContains = common.TypeRelationshipContains
	relationshipDepensOn = common.TypeRelationshipDependsOn

	categoryPackageManager = common.CategoryPackageManager
	packageManagerPURL     = common.TypePackageManagerPURL

	categorySecurity  = common.CategorySecurity
	securityCPE23Type = common.TypeSecurityCPE23Type
	securityAdvisory  = common.TypeSecurityAdvisory
)

// ToSPDX converts ScanResult to SPDX Document
func ToSPDX(r models.ScanResult, toolName string) spdx.Document {
	root := osToSpdxPackage(r)

	packageToURLMap := createPackageToURLMap(r)
	creationInfo := spdxCreationInfo(r, toolName)
	packages, relationships := spdxPackages(r, root, packageToURLMap)

	packages = append(packages, &root)
	relRoot := makeSPDXRelationship(documentSPDXIdentifier, root.PackageSPDXIdentifier, relationshipDescribe)
	relationships = append(relationships, &relRoot)

	doc := spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    documentSPDXIdentifier,
		DocumentName:      root.PackageName,
		DocumentNamespace: fmt.Sprintf("%s/%s-%s-%s", documentNamespace, root.PackageName, root.PackageVersion, uuid.NewString()),
		CreationInfo:      &creationInfo,
		Packages:          packages,
		Relationships:     relationships,
	}

	sortSDPXDocument(&doc)

	return doc
}

// SerializeSPDX serializes SPDX Document to JSON
// Only supports JSON format
func SerializeSPDX(doc spdx.Document) ([]byte, error) {
	return json.MarshalIndent(&doc, "", "  ")
}

func osToSpdxPackage(r models.ScanResult) spdx.Package {
	family := constant.ServerTypePseudo
	if r.Family != "" {
		family = r.Family
	}

	var annotations []spdx.Annotation
	annotations = appendAnnotation(annotations, "OsFamily", family, r.ReportedAt)
	if r.RunningKernel.Release != "" {
		annotations = appendAnnotation(annotations, "RunningKernelRelease", r.RunningKernel.Release, r.ReportedAt)
	}
	if r.RunningKernel.Version != "" {
		annotations = appendAnnotation(annotations, "RunningKernelVersion", r.RunningKernel.Version, r.ReportedAt)
	}

	return spdx.Package{
		PackageSPDXIdentifier:     generateSDPXIDentifier(elementOperatingSystem),
		PackageName:               family,
		PackageVersion:            r.Release,
		PackageDownloadLocation:   valueNone,
		Annotations:               annotations,
		PackageExternalReferences: nil,
		PrimaryPackagePurpose:     packagePurposeOS,
	}
}

func spdxCreationInfo(result models.ScanResult, toolName string) spdx.CreationInfo {
	if toolName == "" {
		toolName = fmt.Sprintf("%s-%s-%s", creatorTool, config.Version, config.Revision)
	}
	if result.ReportedVersion != "" {
		toolName = fmt.Sprintf("%s-%s", creatorTool, result.ReportedVersion)
	}

	return spdx.CreationInfo{
		Creators: []common.Creator{
			{Creator: creatorOrganization, CreatorType: "Organization"},
			{Creator: toolName, CreatorType: "Tool"},
		},
		Created: result.ReportedAt.Format(time.RFC3339),
	}
}

func spdxPackages(result models.ScanResult, root spdx.Package, packageToURLMap map[string][]string) ([]*spdx.Package, []*spdx.Relationship) {
	var packages []*spdx.Package
	var relationships []*spdx.Relationship

	if ospkgs := ospkgToSPDXPackages(result, packageToURLMap); len(ospkgs) > 0 {
		for _, pack := range ospkgs {
			packages = append(packages, &pack)
			rel := makeSPDXRelationship(root.PackageSPDXIdentifier, pack.PackageSPDXIdentifier, relationshipContains)
			relationships = append(relationships, &rel)
		}
	}

	if cpePkgs := cpeToSPDXPackages(result, packageToURLMap); len(cpePkgs) > 0 {
		packages = append(packages, &cpePkgs[0])
		relCpe := makeSPDXRelationship(root.PackageSPDXIdentifier, cpePkgs[0].PackageSPDXIdentifier, relationshipContains)
		relationships = append(relationships, &relCpe)
		for _, pack := range cpePkgs[1:] {
			packages = append(packages, &pack)
			rel := makeSPDXRelationship(cpePkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, relationshipContains)
			relationships = append(relationships, &rel)
		}
	}

	for _, libScanner := range result.LibraryScanners {
		if libpkgs := libpkgToSPDXPackages(libScanner, packageToURLMap, result.ReportedAt); len(libpkgs) > 0 {
			packages = append(packages, &libpkgs[0])
			relLib := makeSPDXRelationship(root.PackageSPDXIdentifier, libpkgs[0].PackageSPDXIdentifier, relationshipContains)
			relationships = append(relationships, &relLib)
			for _, pack := range libpkgs[1:] {
				packages = append(packages, &pack)
				rel := makeSPDXRelationship(libpkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, relationshipDepensOn)
				relationships = append(relationships, &rel)
			}
		}
	}

	for _, ghm := range result.GitHubManifests {
		if ghpkgs := ghpkgToSPDXPackages(ghm, packageToURLMap, result.ReportedAt); len(ghpkgs) > 0 {
			packages = append(packages, &ghpkgs[0])
			relGhm := makeSPDXRelationship(root.PackageSPDXIdentifier, ghpkgs[0].PackageSPDXIdentifier, relationshipContains)
			relationships = append(relationships, &relGhm)
			for _, pack := range ghpkgs[1:] {
				packages = append(packages, &pack)
				rel := makeSPDXRelationship(ghpkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, relationshipDepensOn)
				relationships = append(relationships, &rel)
			}
		}
	}

	if wppkgs := wppkgToSPDXPackages(result.WordPressPackages, packageToURLMap, result.ReportedAt); len(wppkgs) > 0 {
		packages = append(packages, &wppkgs[0])
		relWp := makeSPDXRelationship(root.PackageSPDXIdentifier, wppkgs[0].PackageSPDXIdentifier, relationshipContains)
		relationships = append(relationships, &relWp)
		for _, pack := range wppkgs[1:] {
			packages = append(packages, &pack)
			rel := makeSPDXRelationship(wppkgs[0].PackageSPDXIdentifier, pack.PackageSPDXIdentifier, relationshipDepensOn)
			relationships = append(relationships, &rel)
		}
	}

	return packages, relationships
}

func ospkgToSPDXPackages(r models.ScanResult, packageToURLMap map[string][]string) []spdx.Package {
	if r.Family == "" || len(r.Packages) == 0 {
		return []spdx.Package{}
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
		externalRefs = appendExternalRefs(externalRefs, categoryPackageManager, packageManagerPURL, purl.String())

		for _, url := range packageToURLMap[pack.Name] {
			externalRefs = appendExternalRefs(externalRefs, categorySecurity, securityAdvisory, url)
		}

		spdxPackage := spdx.Package{
			PackageSPDXIdentifier: generateSDPXIDentifier(elementPackage),
			PackageName:           pack.Name,
			PackageVersion: func() string {
				if pack.Release == "" {
					return pack.Version
				}
				return fmt.Sprintf("%s-%s", pack.Version, pack.Release)
			}(),
			PackageDownloadLocation:   valueNone,
			Annotations:               annotations,
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     packagePurposeLibrary,
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
		return []spdx.Package{}
	}

	packages := make([]spdx.Package, 0, 1+len(cpes))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier:   generateSDPXIDentifier(elementPackage),
		PackageName:             "CPEs",
		PackageDownloadLocation: valueNone,
		Annotations:             appendAnnotation(nil, "Type", "CPE", r.ReportedAt),
		PrimaryPackagePurpose:   packagePurposeApplication,
	})

	for cpe := range cpes {
		var externalRefs []*spdx.PackageExternalReference
		externalRefs = appendExternalRefs(externalRefs, categorySecurity, securityCPE23Type, cpe)

		for _, url := range packageToURLMap[cpe] {
			externalRefs = appendExternalRefs(externalRefs, categorySecurity, securityAdvisory, url)
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     generateSDPXIDentifier(elementPackage),
			PackageName:               cpe,
			PackageDownloadLocation:   valueNone,
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     packagePurposeLibrary,
		})
	}

	return packages
}

func libpkgToSPDXPackages(libScanner models.LibraryScanner, packageToURLMap map[string][]string, reportedAt time.Time) []spdx.Package {
	if len(libScanner.Libs) == 0 {
		return []spdx.Package{}
	}

	packages := make([]spdx.Package, 0, 1+len(libScanner.Libs))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier:   generateSDPXIDentifier(elementPackage),
		PackageName:             libScanner.LockfilePath,
		PackageDownloadLocation: valueNone,
		Annotations:             appendAnnotation(nil, "Type", string(libScanner.Type), reportedAt),
		PrimaryPackagePurpose:   packagePurposeApplication,
	})

	for _, lib := range libScanner.Libs {
		var externalRefs []*spdx.PackageExternalReference
		purl := libPkgToPURL(libScanner, lib)
		externalRefs = appendExternalRefs(externalRefs, categoryPackageManager, packageManagerPURL, purl.String())

		libkey := fmt.Sprintf("lib:%s:%s", libScanner.LockfilePath, lib.Name)
		for _, url := range packageToURLMap[libkey] {
			externalRefs = appendExternalRefs(externalRefs, categorySecurity, securityAdvisory, url)
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     generateSDPXIDentifier(elementPackage),
			PackageName:               lib.Name,
			PackageVersion:            lib.Version,
			PackageDownloadLocation:   valueNone,
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     packagePurposeLibrary,
		})
	}

	return packages
}

func ghpkgToSPDXPackages(ghm models.DependencyGraphManifest, packageToURLMap map[string][]string, reportedAt time.Time) []spdx.Package {
	if len(ghm.Dependencies) == 0 {
		return []spdx.Package{}
	}

	packages := make([]spdx.Package, 0, 1+len(ghm.Dependencies))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier:   generateSDPXIDentifier(elementPackage),
		PackageName:             ghm.BlobPath,
		PackageDownloadLocation: valueNone,
		Annotations:             appendAnnotation(nil, "Type", string(ghm.Ecosystem()), reportedAt),
		PrimaryPackagePurpose:   packagePurposeApplication,
	})

	for _, dep := range ghm.Dependencies {
		var externalRefs []*spdx.PackageExternalReference
		purl := ghPkgToPURL(ghm, dep)
		externalRefs = appendExternalRefs(externalRefs, categoryPackageManager, packageManagerPURL, purl.String())

		ghkey := fmt.Sprintf("gh:%s:%s", ghm.RepoURLFilename(), dep.PackageName)
		for _, url := range packageToURLMap[ghkey] {
			externalRefs = appendExternalRefs(externalRefs, categorySecurity, securityAdvisory, url)
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     generateSDPXIDentifier(elementPackage),
			PackageName:               dep.PackageName,
			PackageVersion:            dep.Version(),
			PackageDownloadLocation:   valueNone,
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     packagePurposeLibrary,
		})
	}

	return packages
}

func wppkgToSPDXPackages(wppkgs models.WordPressPackages, packageToURLMap map[string][]string, reportedAt time.Time) []spdx.Package {
	if len(wppkgs) == 0 {
		return []spdx.Package{}
	}

	packages := make([]spdx.Package, 0, 1+len(wppkgs))

	packages = append(packages, spdx.Package{
		PackageSPDXIdentifier:   generateSDPXIDentifier(elementPackage),
		PackageName:             "wordpress",
		PackageDownloadLocation: valueNone,
		Annotations:             appendAnnotation(nil, "Type", "WordPress", reportedAt),
		PrimaryPackagePurpose:   packagePurposeApplication,
	})

	for _, wppkg := range wppkgs {
		var externalRefs []*spdx.PackageExternalReference
		purl := wpPkgToPURL(wppkg)
		externalRefs = appendExternalRefs(externalRefs, categoryPackageManager, packageManagerPURL, purl.String())

		wpkey := fmt.Sprintf("wp:%s", wppkg.Name)
		for _, url := range packageToURLMap[wpkey] {
			externalRefs = appendExternalRefs(externalRefs, categorySecurity, securityAdvisory, url)
		}

		packages = append(packages, spdx.Package{
			PackageSPDXIdentifier:     generateSDPXIDentifier(elementPackage),
			PackageName:               wppkg.Name,
			PackageVersion:            wppkg.Version,
			PackageDownloadLocation:   valueNone,
			PackageExternalReferences: externalRefs,
			PrimaryPackagePurpose:     packagePurposeLibrary,
		})
	}

	return packages
}

func generateSDPXIDentifier(packageType string) spdx.ElementID {
	return spdx.ElementID(fmt.Sprintf("%s-%016x", packageType, rand.Uint64()))
}

func appendAnnotation(annotations []spdx.Annotation, key, value string, reportedAt time.Time) []spdx.Annotation {
	if value == "" {
		return annotations
	}
	return append(annotations, spdx.Annotation{
		Annotator: spdx.Annotator{
			Annotator:     fmt.Sprintf("%s:%s", creatorOrganization, creatorTool),
			AnnotatorType: packageAnnotatorTool,
		},
		AnnotationDate:    reportedAt.Format(time.RFC3339),
		AnnotationType:    annotationOther,
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

func makeSPDXRelationship(refA, refB spdx.ElementID, relationship string) spdx.Relationship {
	return spdx.Relationship{
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
	packageURLMap := make(map[string][]string)
	seen := make(map[string]map[string]struct{})

	addURL := func(key, url string) {
		if key == "" || url == "" {
			return
		}
		seenSet, ok := seen[key]
		if !ok {
			seenSet = make(map[string]struct{})
			seen[key] = seenSet
		}
		if _, exists := seenSet[url]; exists {
			return
		}
		seenSet[url] = struct{}{}
		packageURLMap[key] = append(packageURLMap[key], url)
	}

	for _, cve := range r.ScannedCves {
		cveURLSet := make(map[string]struct{})
		for _, contents := range cve.CveContents {
			for _, content := range contents {
				if content.SourceLink != "" {
					cveURLSet[content.SourceLink] = struct{}{}
				}
				for _, ref := range content.References {
					if ref.Link != "" {
						cveURLSet[ref.Link] = struct{}{}
					}
				}
			}
		}
		if len(cveURLSet) == 0 {
			continue
		}

		keySet := make(map[string]struct{})
		for _, p := range cve.AffectedPackages {
			keySet[p.Name] = struct{}{}
		}
		for _, cpe := range cve.CpeURIs {
			keySet[cpe] = struct{}{}
		}
		for _, lf := range cve.LibraryFixedIns {
			if lf.Path != "" && lf.Name != "" {
				keySet[fmt.Sprintf("lib:%s:%s", lf.Path, lf.Name)] = struct{}{}
			}
		}
		for _, alert := range cve.GitHubSecurityAlerts {
			if alert.RepoURLManifestPath() != "" && alert.Package.Name != "" {
				keySet[fmt.Sprintf("gh:%s:%s", alert.RepoURLManifestPath(), alert.Package.Name)] = struct{}{}
			}
		}
		for _, wp := range cve.WpPackageFixStats {
			keySet[fmt.Sprintf("wp:%s", wp.Name)] = struct{}{}
		}

		for key := range keySet {
			for url := range cveURLSet {
				addURL(key, url)
			}
		}
	}

	return packageURLMap
}

func sortSDPXDocument(doc *spdx.Document) {
	slices.SortFunc(doc.Packages, func(pi, pj *spdx.Package) int {
		return cmp.Or(
			cmp.Compare(pi.PackageName, pj.PackageName),
			cmp.Compare(pi.PackageVersion, pj.PackageVersion),
			cmp.Compare(pi.PackageSPDXIdentifier, pj.PackageSPDXIdentifier),
		)
	})

	for _, p := range doc.Packages {
		if len(p.PackageExternalReferences) > 1 {
			slices.SortFunc(p.PackageExternalReferences, func(a, b *spdx.PackageExternalReference) int {
				return cmp.Or(
					cmp.Compare(a.Category, b.Category),
					cmp.Compare(a.RefType, b.RefType),
					cmp.Compare(a.Locator, b.Locator),
				)
			})
		}

		if len(p.Annotations) > 1 {
			slices.SortFunc(p.Annotations, func(a, b spdx.Annotation) int {
				return cmp.Compare(a.AnnotationComment, b.AnnotationComment)
			})
		}
	}

	slices.SortFunc(doc.Relationships, func(ri, rj *spdx.Relationship) int {
		return cmp.Or(
			cmp.Compare(ri.RefA.ElementRefID, rj.RefA.ElementRefID),
			cmp.Compare(ri.RefB.ElementRefID, rj.RefB.ElementRefID),
			cmp.Compare(ri.Relationship, rj.Relationship),
		)
	})
}
