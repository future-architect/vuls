package gost

import (
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
	"strings"
)

// Pseudo is Gost client except for RedHat family and Debian
type Pseudo struct {
	Base
}

// DetectUnfixed fills cve information that has in Gost
func (pse Pseudo) DetectUnfixed(driver db.DB, r *models.ScanResult, _ bool) (int, error) {
	return 0, nil
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
