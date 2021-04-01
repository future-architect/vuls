// +build !scanner

package oval

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// Alpine is the struct of Alpine Linux
type Alpine struct {
	Base
}

// NewAlpine creates OVAL client for SUSE
func NewAlpine(cnf config.VulnDictInterface) Alpine {
	return Alpine{
		Base{
			family: constant.Alpine,
			Cnf:    cnf,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Alpine) FillWithOval(r *models.ScanResult) (nCVEs int, err error) {
	var relatedDefs ovalResult
	if o.Cnf.IsFetchViaHTTP() {
		if relatedDefs, err = getDefsByPackNameViaHTTP(r, o.Cnf.GetURL()); err != nil {
			return 0, err
		}
	} else {
		driver, err := newOvalDB(o.Cnf, r.Family)
		if err != nil {
			return 0, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

		if relatedDefs, err = getDefsByPackNameFromOvalDB(driver, r); err != nil {
			return 0, err
		}
	}
	for _, defPacks := range relatedDefs.entries {
		o.update(r, defPacks)
	}

	return len(relatedDefs.entries), nil
}

func (o Alpine) update(r *models.ScanResult, defPacks defPacks) {
	cveID := defPacks.def.Advisory.Cves[0].CveID
	vinfo, ok := r.ScannedCves[cveID]
	if !ok {
		logging.Log.Debugf("%s is newly detected by OVAL", cveID)
		vinfo = models.VulnInfo{
			CveID:       cveID,
			Confidences: []models.Confidence{models.OvalMatch},
		}
	}

	vinfo.AffectedPackages = defPacks.toPackStatuses()
	vinfo.AffectedPackages.Sort()
	r.ScannedCves[cveID] = vinfo
}
