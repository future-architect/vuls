package oval

import (
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// Client is the interface of OVAL client.
type Client interface {
	FillCveInfoFromOvalDB(r *models.ScanResult) error
}

func getPackages(r *models.ScanResult, d *ovalmodels.Definition) models.Packages {
	packages := models.Packages{}
	for _, affectedPack := range d.AffectedPacks {
		pack, _ := r.Packages[affectedPack.Name]
		//  pack.Changelog = models.Changelog{}
		packages[affectedPack.Name] = pack
	}
	return packages
}
