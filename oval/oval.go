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
	var packages models.Packages
	for _, pack := range d.AffectedPacks {
		for _, p := range r.Packages {
			if pack.Name == p.Name {
				p.Changelog = models.Changelog{}
				packages = append(packages, p)
				break
			}
		}
	}
	return packages
}
