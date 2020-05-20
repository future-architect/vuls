package parser

import (
	"encoding/json"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/future-architect/vuls/models"
)

// Parse :
func Parse(vulnJSON []byte, scanResult *models.ScanResult) (result *models.ScanResult, err error) {
	var trivyResults report.Results
	if err = json.Unmarshal(vulnJSON, &trivyResults); err != nil {
		return nil, err
	}

	pkgs := models.Packages{}
	for _, trivyResult := range trivyResults {
		vulnInfos := models.VulnInfos{}
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
					CveContents: models.CveContents{
						models.Trivy: models.CveContent{
							Cvss3Severity: vuln.Severity,
							// TODO :
							References: models.References{},
						},
					},
					LibraryFixedIns: models.LibraryFixedIns{},
					// VulnType : "",
				}
			}
			vulnInfo := vulnInfos[vuln.VulnerabilityID]
			packageFixStatuses := vulnInfo.AffectedPackages
			var notFixedYet bool
			// TODO :
			fixState := ""
			if len(vuln.FixedVersion) == 0 {
				notFixedYet = true
				fixState = "not fixed yet"
			}
			packageFixStatuses = append(packageFixStatuses, models.PackageFixStatus{
				Name:        vuln.PkgName,
				NotFixedYet: notFixedYet,
				FixState:    fixState,
				FixedIn:     vuln.FixedVersion,
			})
			vulnInfo.AffectedPackages = packageFixStatuses
			vulnInfos[vuln.VulnerabilityID] = vulnInfo
			scanResult.ScannedCves = vulnInfos

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
		}
		scanResult.Packages = pkgs
	}
	return scanResult, nil
}
