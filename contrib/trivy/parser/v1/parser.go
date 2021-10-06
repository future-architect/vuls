package v1

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

type ParserV1 struct {
}

// Parse :
func (p ParserV1) Parse(vulnJSON []byte, scanResult *models.ScanResult) (result *models.ScanResult, err error) {
	var trivyResults report.Results
	if err = json.Unmarshal(vulnJSON, &trivyResults); err != nil {
		return nil, err
	}

	pkgs := models.Packages{}
	vulnInfos := models.VulnInfos{}
	uniqueLibraryScannerPaths := map[string]models.LibraryScanner{}
	for _, trivyResult := range trivyResults {
		setScanResultMeta(scanResult, &trivyResult)
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
				vulnInfo.LibraryFixedIns = append(vulnInfo.LibraryFixedIns, models.LibraryFixedIn{
					Key:     trivyResult.Type,
					Name:    vuln.PkgName,
					Path:    trivyResult.Target,
					FixedIn: vuln.FixedVersion,
				})
				libScanner := uniqueLibraryScannerPaths[trivyResult.Target]
				libScanner.Type = trivyResult.Type
				libScanner.Libs = append(libScanner.Libs, types.Library{
					Name:    vuln.PkgName,
					Version: vuln.InstalledVersion,
				})
				uniqueLibraryScannerPaths[trivyResult.Target] = libScanner
			}
			vulnInfos[vuln.VulnerabilityID] = vulnInfo
		}
	}
	// flatten and unique libraries
	libraryScanners := make([]models.LibraryScanner, 0, len(uniqueLibraryScannerPaths))
	for path, v := range uniqueLibraryScannerPaths {
		uniqueLibrary := map[string]types.Library{}
		for _, lib := range v.Libs {
			uniqueLibrary[lib.Name+lib.Version] = lib
		}

		var libraries []types.Library
		for _, library := range uniqueLibrary {
			libraries = append(libraries, library)
		}

		sort.Slice(libraries, func(i, j int) bool {
			return libraries[i].Name < libraries[j].Name
		})

		libscanner := models.LibraryScanner{
			Type: v.Type,
			Path: path,
			Libs: libraries,
		}
		libraryScanners = append(libraryScanners, libscanner)
	}
	sort.Slice(libraryScanners, func(i, j int) bool {
		return libraryScanners[i].Path < libraryScanners[j].Path
	})
	scanResult.ScannedCves = vulnInfos
	scanResult.Packages = pkgs
	scanResult.LibraryScanners = libraryScanners
	return scanResult, nil
}

const trivyTarget = "trivy-target"

func setScanResultMeta(scanResult *models.ScanResult, trivyResult *report.Result) {
	if isTrivySupportedOS(trivyResult.Type) {
		scanResult.Family = trivyResult.Type
		scanResult.ServerName = trivyResult.Target
		scanResult.Optional = map[string]interface{}{
			trivyTarget: trivyResult.Target,
		}
	} else if isTrivySupportedLib(trivyResult.Type) {
		if scanResult.Family == "" {
			scanResult.Family = constant.ServerTypePseudo
		}
		if scanResult.ServerName == "" {
			scanResult.ServerName = "library scan by trivy"
		}
		if _, ok := scanResult.Optional[trivyTarget]; !ok {
			scanResult.Optional = map[string]interface{}{
				trivyTarget: trivyResult.Target,
			}
		}
	}
	scanResult.ScannedAt = time.Now()
	scanResult.ScannedBy = "trivy"
	scanResult.ScannedVia = "trivy"
}

// isTrivySupportedOS :
func isTrivySupportedOS(family string) bool {
	supportedFamilies := map[string]interface{}{
		os.RedHat:             struct{}{},
		os.Debian:             struct{}{},
		os.Ubuntu:             struct{}{},
		os.CentOS:             struct{}{},
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
	}
	_, ok := supportedFamilies[family]
	return ok
}

func isTrivySupportedLib(typestr string) bool {
	supportedLibs := map[string]interface{}{
		ftypes.Bundler:  struct{}{},
		ftypes.Cargo:    struct{}{},
		ftypes.Composer: struct{}{},
		ftypes.Npm:      struct{}{},
		ftypes.NuGet:    struct{}{},
		ftypes.Pip:      struct{}{},
		ftypes.Pipenv:   struct{}{},
		ftypes.Poetry:   struct{}{},
		ftypes.Yarn:     struct{}{},
		ftypes.Jar:      struct{}{},
		ftypes.GoBinary: struct{}{},
		ftypes.GoMod:    struct{}{},
	}
	_, ok := supportedLibs[typestr]
	return ok
}
