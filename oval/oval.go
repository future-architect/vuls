package oval

import (
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// OvalClient is the interface of OVAL client.
type OvalClient interface {
	FillCveInfoFromOvalDB(r models.ScanResult) (*models.ScanResult, error)
}

func getPackageInfoList(r models.ScanResult, d ovalmodels.Definition) models.PackageInfoList {
	var packageInfoList models.PackageInfoList
	for _, pack := range d.AffectedPacks {
		for _, p := range r.Packages {
			if pack.Name == p.Name {
				packageInfoList = append(packageInfoList, p)
				break
			}
		}
	}
	return packageInfoList
}
