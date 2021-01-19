// +build !scanner

package gost

import (
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
)

// Base is a base struct
type Base struct {
}

// FillCVEsWithRedHat fills cve information that has in Gost
func (b Base) FillCVEsWithRedHat(driver db.DB, r *models.ScanResult) error {
	return RedHat{}.fillCvesWithRedHatAPI(driver, r)
}
