package v2

import (
	"encoding/json"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/contrib/trivy/pkg"
	"github.com/future-architect/vuls/models"
)

// ParserV2 is a parser for scheme v2
type ParserV2 struct {
}

// Parse trivy's JSON and convert to the Vuls struct
func (p ParserV2) Parse(vulnJSON []byte) (result *models.ScanResult, err error) {
	var report report.Report
	if err = json.Unmarshal(vulnJSON, &report); err != nil {
		return nil, err
	}

	scanResult, err := pkg.Convert(report.Results)
	if err != nil {
		return nil, err
	}

	setScanResultMeta(scanResult, &report)
	return scanResult, nil
}

func setScanResultMeta(scanResult *models.ScanResult, report *report.Report) {
	for _, r := range report.Results {
		const trivyTarget = "trivy-target"
		if pkg.IsTrivySupportedOS(r.Type) {
			scanResult.Family = r.Type
			scanResult.ServerName = r.Target
			scanResult.Optional = map[string]interface{}{
				trivyTarget: r.Target,
			}
		} else if pkg.IsTrivySupportedLib(r.Type) {
			if scanResult.Family == "" {
				scanResult.Family = constant.ServerTypePseudo
			}
			if scanResult.ServerName == "" {
				scanResult.ServerName = "library scan by trivy"
			}
			if _, ok := scanResult.Optional[trivyTarget]; !ok {
				scanResult.Optional = map[string]interface{}{
					trivyTarget: r.Target,
				}
			}
		}
		scanResult.ScannedAt = time.Now()
		scanResult.ScannedBy = "trivy"
		scanResult.ScannedVia = "trivy"
	}
}
