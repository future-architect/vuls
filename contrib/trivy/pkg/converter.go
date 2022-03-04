package pkg

import (
	"sort"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"

	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/future-architect/vuls/models"
)

// Convert :
func Convert(results types.Results) (result *models.ScanResult, err error) {
	scanResult := &models.ScanResult{
		JSONVersion: models.JSONVersion,
		ScannedCves: models.VulnInfos{},
	}

	pkgs := models.Packages{}
	srcPkgs := models.SrcPackages{}
	vulnInfos := models.VulnInfos{}
	uniqueLibraryScannerPaths := map[string]models.LibraryScanner{}
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

			sort.Slice(references, func(i, j int) bool {
				return references[i].Link < references[j].Link
			})

			var published time.Time
			if vuln.PublishedDate != nil {
				published = *vuln.PublishedDate
			}

			var lastModified time.Time
			if vuln.LastModifiedDate != nil {
				lastModified = *vuln.LastModifiedDate
			}

			vulnInfo.CveContents = models.CveContents{
				models.Trivy: []models.CveContent{{
					Cvss3Severity: vuln.Severity,
					References:    references,
					Title:         vuln.Title,
					Summary:       vuln.Description,
					Published:     published,
					LastModified:  lastModified,
				}},
			}
			// do onlyIif image type is Vuln
			if IsTrivySupportedOS(trivyResult.Type) {
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
				vulnInfo.LibraryFixedIns = append(vulnInfo.LibraryFixedIns, models.LibraryFixedIn{
					Key:     trivyResult.Type,
					Name:    vuln.PkgName,
					Path:    trivyResult.Target,
					FixedIn: vuln.FixedVersion,
				})
				libScanner := uniqueLibraryScannerPaths[trivyResult.Target]
				libScanner.Type = trivyResult.Type
				libScanner.Libs = append(libScanner.Libs, models.Library{
					Name:     vuln.PkgName,
					Version:  vuln.InstalledVersion,
					FilePath: vuln.PkgPath,
				})
				uniqueLibraryScannerPaths[trivyResult.Target] = libScanner
			}
			vulnInfos[vuln.VulnerabilityID] = vulnInfo
		}

		// --list-all-pkgs flg of trivy will output all installed packages, so collect them.
		if trivyResult.Class == types.ClassOSPkg {
			for _, p := range trivyResult.Packages {
				pkgs[p.Name] = models.Package{
					Name:    p.Name,
					Version: p.Version,
				}
				if p.Name != p.SrcName {
					if v, ok := srcPkgs[p.SrcName]; !ok {
						srcPkgs[p.SrcName] = models.SrcPackage{
							Name:        p.SrcName,
							Version:     p.SrcVersion,
							BinaryNames: []string{p.Name},
						}
					} else {
						v.AddBinaryName(p.Name)
						srcPkgs[p.SrcName] = v
					}
				}
			}
		} else if trivyResult.Class == types.ClassLangPkg {
			libScanner := uniqueLibraryScannerPaths[trivyResult.Target]
			libScanner.Type = trivyResult.Type
			for _, p := range trivyResult.Packages {
				libScanner.Libs = append(libScanner.Libs, models.Library{
					Name:     p.Name,
					Version:  p.Version,
					FilePath: p.FilePath,
				})
			}
			uniqueLibraryScannerPaths[trivyResult.Target] = libScanner
		}
	}

	// flatten and unique libraries
	libraryScanners := make([]models.LibraryScanner, 0, len(uniqueLibraryScannerPaths))
	for path, v := range uniqueLibraryScannerPaths {
		uniqueLibrary := map[string]models.Library{}
		for _, lib := range v.Libs {
			uniqueLibrary[lib.Name+lib.Version] = lib
		}

		var libraries []models.Library
		for _, library := range uniqueLibrary {
			libraries = append(libraries, library)
		}

		sort.Slice(libraries, func(i, j int) bool {
			return libraries[i].Name < libraries[j].Name
		})

		libscanner := models.LibraryScanner{
			Type:         v.Type,
			LockfilePath: path,
			Libs:         libraries,
		}
		libraryScanners = append(libraryScanners, libscanner)
	}
	sort.Slice(libraryScanners, func(i, j int) bool {
		return libraryScanners[i].LockfilePath < libraryScanners[j].LockfilePath
	})
	scanResult.ScannedCves = vulnInfos
	scanResult.Packages = pkgs
	scanResult.SrcPackages = srcPkgs
	scanResult.LibraryScanners = libraryScanners
	return scanResult, nil
}

// IsTrivySupportedOS :
func IsTrivySupportedOS(family string) bool {
	supportedFamilies := map[string]interface{}{
		os.RedHat:             struct{}{},
		os.Debian:             struct{}{},
		os.Ubuntu:             struct{}{},
		os.CentOS:             struct{}{},
		os.Rocky:              struct{}{},
		os.Alma:               struct{}{},
		os.Fedora:             struct{}{},
		os.Amazon:             struct{}{},
		os.Oracle:             struct{}{},
		os.Windows:            struct{}{},
		os.OpenSUSE:           struct{}{},
		os.OpenSUSELeap:       struct{}{},
		os.OpenSUSETumbleweed: struct{}{},
		os.SLES:               struct{}{},
		os.Photon:             struct{}{},
		os.Alpine:             struct{}{},
		// os.Fedora:             struct{}{}, not supported yet
	}
	_, ok := supportedFamilies[family]
	return ok
}

// IsTrivySupportedLib :
func IsTrivySupportedLib(typestr string) bool {
	supportedLibs := map[string]interface{}{
		ftypes.Bundler:   struct{}{},
		ftypes.GemSpec:   struct{}{},
		ftypes.Cargo:     struct{}{},
		ftypes.Composer:  struct{}{},
		ftypes.Npm:       struct{}{},
		ftypes.NuGet:     struct{}{},
		ftypes.Pip:       struct{}{},
		ftypes.Pipenv:    struct{}{},
		ftypes.Poetry:    struct{}{},
		ftypes.PythonPkg: struct{}{},
		ftypes.NodePkg:   struct{}{},
		ftypes.Yarn:      struct{}{},
		ftypes.Jar:       struct{}{},
		ftypes.Pom:       struct{}{},
		ftypes.GoBinary:  struct{}{},
		ftypes.GoMod:     struct{}{},
	}
	_, ok := supportedLibs[typestr]
	return ok
}
