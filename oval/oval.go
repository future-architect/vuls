package oval

import (
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

// Client is the interface of OVAL client.
type Client interface {
	FillCveInfoFromOvalDB(r *models.ScanResult) error
}

func getPackages(r *models.ScanResult, d *ovalmodels.Definition) (names []string) {
	for _, affectedPack := range d.AffectedPacks {
		names = append(names, affectedPack.Name)
	}
	return
}
