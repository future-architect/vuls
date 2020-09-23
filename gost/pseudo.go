package gost

import (
	"strings"

	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
)

// Pseudo is Gost client except for RedHat family and Debian
type Pseudo struct {
	Base
}

// DetectCVEs fills cve information that has in Gost
func (pse Pseudo) DetectCVEs(driver db.DB, r *models.ScanResult, _ bool) (int, error) {
	return 0, nil
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
