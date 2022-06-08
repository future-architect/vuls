package v2

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/contrib/trivy/pkg"
	"github.com/future-architect/vuls/models"
)

// ParserV2 is a parser for scheme v2
type ParserV2 struct {
}

// Parse trivy's JSON and convert to the Vuls struct
func (p ParserV2) Parse(vulnJSON []byte) (result *models.ScanResult, err error) {
	var report types.Report
	if err = json.Unmarshal(vulnJSON, &report); err != nil {
		return nil, err
	}

	scanResult, err := pkg.Convert(report.Results)
	if err != nil {
		return nil, err
	}

	if err := setScanResultMeta(scanResult, &report); err != nil {
		return nil, err
	}
	return scanResult, nil
}

var dockerTagPattern = regexp.MustCompile(`^(.*):(.*)$`)

func setScanResultMeta(scanResult *models.ScanResult, report *types.Report) error {
	if len(report.Results) == 0 {
		return xerrors.Errorf("scanned images or libraries are not supported by Trivy. see https://aquasecurity.github.io/trivy/dev/vulnerability/detection/os/, https://aquasecurity.github.io/trivy/dev/vulnerability/detection/language/")
	}

	scanResult.ServerName = report.ArtifactName
	if report.ArtifactType == "container_image" {
		matches := dockerTagPattern.FindStringSubmatch(report.ArtifactName)
		var imageName, imageTag string
		if 2 < len(matches) {
			// including the image tag
			imageName = matches[1]
			imageTag = matches[2]
		} else {
			// no image tag
			imageName = report.ArtifactName
			imageTag = "latest" // Complement if the tag is omitted
		}
		scanResult.ServerName = fmt.Sprintf("%s:%s", imageName, imageTag)
		if scanResult.Optional == nil {
			scanResult.Optional = map[string]interface{}{}
		}
		scanResult.Optional["TRIVY_IMAGE_NAME"] = imageName
		scanResult.Optional["TRIVY_IMAGE_TAG"] = imageTag
	}

	if report.Metadata.OS != nil {
		scanResult.Family = report.Metadata.OS.Family
		scanResult.Release = report.Metadata.OS.Name
	} else {
		scanResult.Family = constant.ServerTypePseudo
	}

	scanResult.ScannedAt = time.Now()
	scanResult.ScannedBy = "trivy"
	scanResult.ScannedVia = "trivy"

	return nil
}
