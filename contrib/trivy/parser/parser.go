package parser

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/future-architect/vuls/models"
)

// Parse :
func Parse(vulnJSON []byte, scanResult *models.ScanResult) (result *models.ScanResult, err error) {
	var trivyResults report.Results
	if err = json.Unmarshal(vulnJSON, &trivyResults); err != nil {
		return nil, err
	}

	pkgs := models.Packages{}
	vulnInfos := models.VulnInfos{}
	uniqueLibraryScanners := map[string]models.LibraryScanner{}
	for _, trivyResult := range trivyResults {
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
			packageFixStatuses := vulnInfo.AffectedPackages
			var notFixedYet bool
			fixState := ""
			if len(vuln.FixedVersion) == 0 {
				notFixedYet = true
				fixState = "Affected"
			}
			packageFixStatuses = append(packageFixStatuses, models.PackageFixStatus{
				Name:        vuln.PkgName,
				NotFixedYet: notFixedYet,
				FixState:    fixState,
				FixedIn:     vuln.FixedVersion,
			})
			vulnInfo.AffectedPackages = packageFixStatuses

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

			vulnInfo.CveContents = models.CveContents{
				models.Trivy: models.CveContent{
					Cvss3Severity: vuln.Severity,
					References:    references,
				},
			}
			// imageのVulnの時のみ処理
			if IsTrivySupportedOS(trivyResult.Type) {
				pkgs[vuln.PkgName] = models.Package{
					Name:    vuln.PkgName,
					Version: vuln.InstalledVersion,
				}
				scanResult.Family = trivyResult.Type
				scanResult.ServerName = trivyResult.Target
				scanResult.Optional = map[string]interface{}{
					"trivy-target": trivyResult.Target,
				}
				scanResult.ScannedAt = time.Now()
				scanResult.ScannedBy = "trivy"
				scanResult.ScannedVia = "trivy"
			} else {
				// LibraryScanの結果
				vulnInfo.LibraryFixedIns = append(vulnInfo.LibraryFixedIns, models.LibraryFixedIn{
					Key:     trivyResult.Type,
					Name:    vuln.PkgName,
					FixedIn: vuln.FixedVersion,
				})
				if _, ok := uniqueLibraryScanners[trivyResult.Target]; !ok {
					uniqueLibraryScanners[trivyResult.Target] = models.LibraryScanner{
						Path: trivyResult.Target,
						Libs: []types.Library{
							{
								Name:    vuln.PkgName,
								Version: vuln.InstalledVersion,
							},
						},
					}
				} else {
					libScanner := uniqueLibraryScanners[trivyResult.Target]
					libScanner.Libs = append(libScanner.Libs, types.Library{
						Name:    vuln.PkgName,
						Version: vuln.InstalledVersion,
					})
					sort.Slice(libScanner.Libs, func(i, j int) bool {
						return libScanner.Libs[i].Name < libScanner.Libs[j].Name
					})
					uniqueLibraryScanners[trivyResult.Target] = libScanner
				}
			}
			vulnInfos[vuln.VulnerabilityID] = vulnInfo
		}
	}
	var libraryScanners []models.LibraryScanner
	for _, v := range uniqueLibraryScanners {
		libraryScanners = append(libraryScanners, v)
	}
	sort.Slice(libraryScanners, func(i, j int) bool {
		return libraryScanners[i].Path < libraryScanners[j].Path
	})
	scanResult.ScannedCves = vulnInfos
	scanResult.Packages = pkgs
	scanResult.LibraryScanners = libraryScanners
	return scanResult, nil
}

// IsTrivySupportedOS :
func IsTrivySupportedOS(family string) bool {
	supportedFamilies := []string{
		os.RedHat,
		os.Debian,
		os.Ubuntu,
		os.CentOS,
		os.Fedora,
		os.Amazon,
		os.Oracle,
		os.Windows,
		os.OpenSUSE,
		os.OpenSUSELeap,
		os.OpenSUSETumbleweed,
		os.SLES,
		os.Photon,
		os.Alpine,
	}
	for _, supportedFamily := range supportedFamilies {
		if family == supportedFamily {
			return true
		}
	}
	return false
}
