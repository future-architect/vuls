package scanner

import (
	"github.com/aquasecurity/fanal/types"
	"github.com/future-architect/vuls/models"
)

func convertLibWithScanner(apps []types.Application) ([]models.LibraryScanner, error) {
	scanners := []models.LibraryScanner{}
	for _, app := range apps {
		libs := []models.Library{}
		for _, lib := range app.Libraries {
			libs = append(libs, models.Library{
				Name:    lib.Name,
				Version: lib.Version,
				Path:    lib.FilePath,
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
