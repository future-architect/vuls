//go:build !scanner
// +build !scanner

package oval

import (
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
)

// Arch is the interface for Arch OVAL.
type Arch struct {
	Base
}

// NewArch creates OVAL client for Arch
func NewArch(driver ovaldb.DB, baseURL string) Arch {
	return Arch{
		Base{
			driver:  driver,
			baseURL: baseURL,
			family:  constant.Arch,
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Arch) FillWithOval(_ *models.ScanResult) (nCVEs int, err error) {
	return 0, nil
}
