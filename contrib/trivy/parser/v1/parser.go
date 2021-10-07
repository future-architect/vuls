package v1

import (
	"encoding/json"
	"time"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/contrib/trivy/pkg"
	"github.com/future-architect/vuls/models"
)

// ParserV1 is a parser for scheme v2
type ParserV1 struct {
}

// Parse trivy's JSON and convert to the Vuls struct
func (p ParserV1) Parse(vulnJSON []byte) (result *models.ScanResult, err error) {
	var trivyResults report.Results
	if err = json.Unmarshal(vulnJSON, &trivyResults); err != nil {
		return nil, err
	}
	scanResult, err := pkg.Convert(trivyResults)
	if err != nil {
		return nil, err
	}

	for _, r := range trivyResults {
		setScanResultMeta(scanResult, &r)
	}

	return scanResult, nil
}

func setScanResultMeta(scanResult *models.ScanResult, trivyResult *report.Result) {
	const trivyTarget = "trivy-target"
	if pkg.IsTrivySupportedOS(trivyResult.Type) {
		scanResult.Family = trivyResult.Type
		scanResult.ServerName = trivyResult.Target
		scanResult.Optional = map[string]interface{}{
			trivyTarget: trivyResult.Target,
		}
	} else if pkg.IsTrivySupportedLib(trivyResult.Type) {
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
