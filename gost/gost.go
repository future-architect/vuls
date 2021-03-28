// +build !scanner

package gost

import (
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"

	"github.com/future-architect/vuls/constant"
)

// Client is the interface of OVAL client.
type Client interface {
	DetectCVEs(db.DB, *models.ScanResult, bool) (int, error)
	FillCVEsWithRedHat(db.DB, *models.ScanResult) error
}

// NewClient make Client by family
func NewClient(family string) Client {
	switch family {
	case constant.RedHat, constant.CentOS:
		return RedHat{}
	case constant.Debian, constant.Raspbian:
		return Debian{}
	case constant.Windows:
		return Microsoft{}
	default:
		return Pseudo{}
	}
}
