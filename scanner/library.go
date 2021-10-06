package scanner

import (
	"github.com/aquasecurity/fanal/types"
	"github.com/future-architect/vuls/models"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

func convertLibWithScanner(apps []types.Application) ([]models.LibraryScanner, error) {
	scanners := []models.LibraryScanner{}
	for _, app := range apps {
		libs := []trivyTypes.Library{}
		for _, lib := range app.Libraries {
			libs = append(libs, trivyTypes.Library{
				Name:    lib.Name,
				Version: lib.Version,
			})
		}
		scanners = append(scanners, models.LibraryScanner{
			Type: app.Type,
			Path: app.FilePath,
			Libs: libs,
		})
	}
	return scanners, nil
}
