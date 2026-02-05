package scanner

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

func convertLibWithScanner(apps []ftypes.Application) ([]models.LibraryScanner, error) {
	scanners := make([]models.LibraryScanner, 0, len(apps))
	for _, app := range apps {
		libs := make([]models.Library, 0, len(app.Packages))
		for _, lib := range app.Packages {
			libs = append(libs, models.Library{
				Name:     lib.Name,
				Version:  lib.Version,
				PURL:     newPURL(app.Type, types.Metadata{}, lib),
				FilePath: lib.FilePath,
				Digest:   string(lib.Digest),
				Dev:      lib.Dev,
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

func newPURL(pkgType ftypes.TargetType, metadata types.Metadata, pkg ftypes.Package) string {
	p, err := purl.New(pkgType, metadata, pkg)
	if err != nil {
		logging.Log.Errorf("Failed to create PackageURL: %+v", err)
		return ""
	}
	if p == nil {
		return ""
	}
	return p.Unwrap().ToString()
}
