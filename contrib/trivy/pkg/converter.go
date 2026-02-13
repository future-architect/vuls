package pkg

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	trivydbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/future-architect/vuls/models"
)

// Convert :
func Convert(results types.Results, artifactType ftypes.ArtifactType, artifactName string) (result *models.ScanResult, err error) {
	scanResult := &models.ScanResult{
		JSONVersion: models.JSONVersion,
		ScannedCves: models.VulnInfos{},
	}

	scanmode := func() ftypes.ArtifactType {
		switch artifactType {
		case ftypes.TypeFilesystem:
			// It is not possible to distinguish between fs and rootfs from the artifact type,
			// so we have no choice but to determine whether or not the results contain os-pkg.
			if slices.ContainsFunc(results, func(e types.Result) bool { return e.Class == types.ClassOSPkg }) {
				return "rootfs"
			}
			return ftypes.TypeFilesystem
		default:
			return artifactType
		}
	}()

	pkgs := models.Packages{}
	srcPkgs := models.SrcPackages{}
	vulnInfos := models.VulnInfos{}
	libraryScannerPaths := map[string]models.LibraryScanner{}
	for _, trivyResult := range results {
		for _, vuln := range trivyResult.Vulnerabilities {
			if _, ok := vulnInfos[vuln.VulnerabilityID]; !ok {
				vulnInfos[vuln.VulnerabilityID] = models.VulnInfo{
					CveID: vuln.VulnerabilityID,
					Confidences: models.Confidences{
						{
							Score:           100,
							DetectionMethod: models.TrivyMatchStr,
						},
					},
					AffectedPackages: models.PackageFixStatuses{},
					CveContents:      models.CveContents{},
					LibraryFixedIns:  models.LibraryFixedIns{},
					// VulnType : "",
				}
			}
			vulnInfo := vulnInfos[vuln.VulnerabilityID]
			var notFixedYet bool
			fixState := ""
			if len(vuln.FixedVersion) == 0 {
				notFixedYet = true
				fixState = "Affected"
			}
			var references models.References
			for _, reference := range vuln.References {
				references = append(references, models.Reference{
					Source: "trivy",
					Link:   reference,
				})
			}

			slices.SortFunc(references, func(a, b models.Reference) int {
				return cmp.Compare(a.Link, b.Link)
			})

			var published time.Time
			if vuln.PublishedDate != nil {
				published = *vuln.PublishedDate
			}

			var lastModified time.Time
			if vuln.LastModifiedDate != nil {
				lastModified = *vuln.LastModifiedDate
			}

			for source, severity := range vuln.VendorSeverity {
				severities := []string{trivydbTypes.SeverityNames[severity]}
				if cs, ok := vulnInfo.CveContents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))]; ok {
					for _, c := range cs {
						for _, s := range strings.Split(c.Cvss3Severity, "|") {
							if s != "" && !slices.Contains(severities, s) {
								severities = append(severities, s)
							}
						}
					}
				}
				slices.SortFunc(severities, func(a, b string) int { return -trivydbTypes.CompareSeverityString(a, b) })

				vulnInfo.CveContents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))] = []models.CveContent{{
					Type:          models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source)),
					CveID:         vuln.VulnerabilityID,
					Title:         vuln.Title,
					Summary:       vuln.Description,
					Cvss3Severity: strings.Join(severities, "|"),
					Published:     published,
					LastModified:  lastModified,
					References:    references,
				}}
			}

			for source, cvss := range vuln.CVSS {
				if cs, ok := vulnInfo.CveContents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))]; ok &&
					slices.ContainsFunc(cs, func(c models.CveContent) bool {
						return c.Cvss2Score == cvss.V2Score && c.Cvss2Vector == cvss.V2Vector && c.Cvss3Score == cvss.V3Score && c.Cvss3Vector == cvss.V3Vector && c.Cvss40Score == cvss.V40Score && c.Cvss40Vector == cvss.V40Vector
					}) {
					continue
				}

				vulnInfo.CveContents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))] = append(vulnInfo.CveContents[models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source))], models.CveContent{
					Type:         models.CveContentType(fmt.Sprintf("%s:%s", models.Trivy, source)),
					CveID:        vuln.VulnerabilityID,
					Title:        vuln.Title,
					Summary:      vuln.Description,
					Cvss2Score:   cvss.V2Score,
					Cvss2Vector:  cvss.V2Vector,
					Cvss3Score:   cvss.V3Score,
					Cvss3Vector:  cvss.V3Vector,
					Cvss40Score:  cvss.V40Score,
					Cvss40Vector: cvss.V40Vector,
					Published:    published,
					LastModified: lastModified,
					References:   references,
				})
			}

			// do only if image type is Vuln
			if isTrivySupportedOS(trivyResult.Type) {
				pkgs[vuln.PkgName] = models.Package{
					Name:    vuln.PkgName,
					Version: vuln.InstalledVersion,
				}
				vulnInfo.AffectedPackages = append(vulnInfo.AffectedPackages, models.PackageFixStatus{
					Name:        vuln.PkgName,
					NotFixedYet: notFixedYet,
					FixState:    fixState,
					FixedIn:     vuln.FixedVersion,
				})
			} else {
				lockfilePath := getLockfilePath(scanmode, artifactName, trivyResult.Type, trivyResult.Target, vuln.PkgPath)

				vulnInfo.LibraryFixedIns = append(vulnInfo.LibraryFixedIns, models.LibraryFixedIn{
					Key:     string(trivyResult.Type),
					Name:    vuln.PkgName,
					Version: vuln.InstalledVersion,
					FixedIn: vuln.FixedVersion,
					Path:    lockfilePath,
				})
				libScanner := libraryScannerPaths[lockfilePath]
				libScanner.Type = trivyResult.Type
				libScanner.Libs = append(libScanner.Libs, models.Library{
					Name:     vuln.PkgName,
					Version:  vuln.InstalledVersion,
					FilePath: vuln.PkgPath,
				})
				libraryScannerPaths[lockfilePath] = libScanner
			}
			vulnInfos[vuln.VulnerabilityID] = vulnInfo
		}

		// --list-all-pkgs flg of trivy will output all installed packages, so collect them.
		switch trivyResult.Class {
		case types.ClassOSPkg:
			for _, p := range trivyResult.Packages {
				pv := p.Version
				if p.Release != "" {
					pv = fmt.Sprintf("%s-%s", pv, p.Release)
				}
				if p.Epoch > 0 {
					pv = fmt.Sprintf("%d:%s", p.Epoch, pv)
				}
				pkgs[p.Name] = models.Package{
					Name:    p.Name,
					Version: pv,
					Arch:    p.Arch,
				}

				v, ok := srcPkgs[p.SrcName]
				if !ok {
					sv := p.SrcVersion
					if p.SrcRelease != "" {
						sv = fmt.Sprintf("%s-%s", sv, p.SrcRelease)
					}
					if p.SrcEpoch > 0 {
						sv = fmt.Sprintf("%d:%s", p.SrcEpoch, sv)
					}
					v = models.SrcPackage{
						Name:    p.SrcName,
						Version: sv,
					}
				}
				v.AddBinaryName(p.Name)
				srcPkgs[p.SrcName] = v
			}
		case types.ClassLangPkg:
			for _, p := range trivyResult.Packages {
				lockfilePath := getLockfilePath(scanmode, artifactName, trivyResult.Type, trivyResult.Target, p.FilePath)

				libScanner := libraryScannerPaths[lockfilePath]
				libScanner.Type = trivyResult.Type
				for _, p := range trivyResult.Packages {
					libScanner.Libs = append(libScanner.Libs, models.Library{
						Name:     p.Name,
						Version:  p.Version,
						PURL:     getPURL(p),
						FilePath: p.FilePath,
						Dev:      p.Dev,
					})
				}
				libraryScannerPaths[lockfilePath] = libScanner
			}
		default:
		}
	}

	// flatten and unique libraries
	libraryScanners := make([]models.LibraryScanner, 0, len(libraryScannerPaths))
	for path, v := range libraryScannerPaths {
		uniqueLibrary := map[string]models.Library{}
		for _, lib := range v.Libs {
			uniqueLibrary[lib.Name+lib.Version] = lib
		}

		var libraries []models.Library
		for _, library := range uniqueLibrary {
			libraries = append(libraries, library)
		}

		slices.SortFunc(libraries, func(a, b models.Library) int {
			return cmp.Compare(a.Name, b.Name)
		})

		libscanner := models.LibraryScanner{
			Type:         v.Type,
			LockfilePath: path,
			Libs:         libraries,
		}
		libraryScanners = append(libraryScanners, libscanner)
	}
	slices.SortFunc(libraryScanners, func(a, b models.LibraryScanner) int {
		return cmp.Compare(a.LockfilePath, b.LockfilePath)
	})
	scanResult.ScannedCves = vulnInfos
	scanResult.Packages = pkgs
	scanResult.SrcPackages = srcPkgs
	scanResult.LibraryScanners = libraryScanners
	return scanResult, nil
}

func isTrivySupportedOS(family ftypes.TargetType) bool {
	supportedFamilies := map[ftypes.TargetType]struct{}{
		ftypes.Alma:               {},
		ftypes.Alpine:             {},
		ftypes.Amazon:             {},
		ftypes.Azure:              {},
		ftypes.Bottlerocket:       {},
		ftypes.CBLMariner:         {},
		ftypes.CentOS:             {},
		ftypes.Chainguard:         {},
		ftypes.CoreOS:             {},
		ftypes.Debian:             {},
		ftypes.Echo:               {},
		ftypes.Fedora:             {},
		ftypes.MinimOS:            {},
		ftypes.OpenSUSE:           {},
		ftypes.OpenSUSELeap:       {},
		ftypes.OpenSUSETumbleweed: {},
		ftypes.Oracle:             {},
		ftypes.Photon:             {},
		ftypes.RedHat:             {},
		ftypes.Rocky:              {},
		ftypes.SLEMicro:           {},
		ftypes.SLES:               {},
		ftypes.Ubuntu:             {},
		ftypes.Wolfi:              {},
	}
	_, ok := supportedFamilies[family]
	return ok
}

func getPURL(p ftypes.Package) string {
	if p.Identifier.PURL == nil {
		return ""
	}
	return p.Identifier.PURL.String()
}

func getLockfilePath(scanmode ftypes.ArtifactType, artifactName string, libType ftypes.LangType, target string, libFilepath string) string {
	p := func() string {
		switch libType {
		case ftypes.NodePkg, ftypes.GemSpec, ftypes.PythonPkg:
			if libFilepath == "" {
				return target
			}
			return libFilepath
		case ftypes.Jar:
			if libFilepath == "" {
				return target
			}
			for _, sep := range []string{".jar", ".war", ".par", ".ear"} {
				if lhs, _, ok := strings.Cut(libFilepath, fmt.Sprintf("%s%s", sep, string(os.PathSeparator))); ok {
					return fmt.Sprintf("%s%s", lhs, sep)
				}
			}
			return libFilepath
		default:
			return target
		}
	}()

	switch scanmode {
	case ftypes.TypeContainerImage:
		return filepath.Join(string(os.PathSeparator), p)
	case "rootfs": // rootfs does not have the path passed to the command in artifactName
		return p
	case ftypes.TypeFilesystem, ftypes.TypeRepository:
		if strings.HasSuffix(artifactName, p) {
			return artifactName
		}
		return filepath.Join(artifactName, p)
	default:
		return p
	}
}
