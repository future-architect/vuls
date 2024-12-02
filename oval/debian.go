//go:build !scanner

package oval

import (
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	ovaldb "github.com/vulsio/goval-dictionary/db"
)

// DebianBase is the base struct of Debian and Ubuntu
type DebianBase struct {
	Base
}

// Debian is the interface for Debian OVAL
type Debian struct {
	DebianBase
}

// NewDebian creates OVAL client for Debian
func NewDebian(driver ovaldb.DB, baseURL string) Debian {
	return Debian{
		DebianBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Debian,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Debian) FillWithOval(_ *models.ScanResult) (nCVEs int, err error) {
	return 0, nil
}

// Ubuntu is the interface for Debian OVAL
type Ubuntu struct {
	DebianBase
}

// NewUbuntu creates OVAL client for Debian
func NewUbuntu(driver ovaldb.DB, baseURL string) Ubuntu {
	return Ubuntu{
		DebianBase{
			Base{
				driver:  driver,
				baseURL: baseURL,
				family:  constant.Ubuntu,
			},
		},
	}
}

// FillWithOval returns scan result after updating CVE info by OVAL
func (o Ubuntu) FillWithOval(_ *models.ScanResult) (nCVEs int, err error) {
	return 0, nil
}
