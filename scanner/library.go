package scanner

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/package-url/packageurl-go"
)

func convertLibWithScanner(apps []ftypes.Application) ([]models.LibraryScanner, error) {
	scanners := []models.LibraryScanner{}
	for _, app := range apps {
		libs := []models.Library{}
		for _, lib := range app.Libraries {
			purl := newPURL(app.Type, types.Metadata{}, lib)
			libs = append(libs, models.Library{
				Name:       lib.Name,
				Version:    lib.Version,
				PackageURL: purl.ToString(),
				FilePath:   lib.FilePath,
				Digest:     string(lib.Digest),
			})
		}
		scanners = append(scanners, models.LibraryScanner{
			Type:         app.Type,
			LockfilePath: app.FilePath,
			Libs:         libs,
		})
	}
	return scanners, nil
}

func newPURL(pkgType ftypes.TargetType, metadata types.Metadata, pkg ftypes.Package) *packageurl.PackageURL {
	p, err := purl.New(pkgType, metadata, pkg)
	if err != nil {
		logging.Log.Errorf("Failed to create PackageURL: %+v", err)
		return nil
	}
	return p.Unwrap()
}
