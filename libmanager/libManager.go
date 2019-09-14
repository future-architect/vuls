package libmanager

import (
	"github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/future-architect/vuls/models"
)

// FillLibrary fills LibraryScanner informations
func FillLibrary(r *models.ScanResult) (totalCnt int, err error) {
	// initialize trivy's logger and db
	err = log.InitLogger(false, false)
	if err != nil {
		return 0, err
	}
	if err := db.Init(); err != nil {
		return 0, err
	}
	for _, lib := range r.LibraryScanners {
		vinfos, err := lib.Scan()
		if err != nil {
			return 0, err
		}
		for _, vinfo := range vinfos {
			r.ScannedCves[vinfo.CveID] = vinfo
		}
		totalCnt += len(vinfos)
	}
	db.Close()

	return totalCnt, nil
}
