//go:build !scanner
// +build !scanner

package oval

import (
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
)

// Alpine is the struct of Alpine Linux
type Alpine struct {
	Base
}

// NewAlpine creates OVAL client for SUSE
func NewAlpine(driver ovaldb.DB, baseURL string) Alpine {
	return Alpine{
		Base{
			driver:  driver,
			baseURL: baseURL,
			family:  constant.Alpine,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Alpine) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.driver == nil {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.baseURL); err != nil {
			return 0, err
		}
	} else {
		if relatedDefs, err = getDefsByPackNameFromOvalDB(r, o.driver); err != nil {
			return 0, err
		}
	}
	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	return len(relatedDefs.entries), nil
}

func (o Alpine) update(r *models.ScanResult, defpacks defPacks) {
	cveID := defpacks.def.Advisory.Cves[0].CveID
	vinfo, ok := r.ScannedCves[cveID]
	if !ok {
		logging.Log.Debugf("%s is newly detected by OVAL", cveID)
		vinfo = models.VulnInfo{
			CveID:       cveID,
			Confidences: []models.Confidence{models.OvalMatch},
		}
	}

	vinfo.AffectedPackages = defpacks.toPackStatuses()
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[cveID] = vinfo
}
