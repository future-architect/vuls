package gost

import (
	cnf "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
)

// Client is the interface of OVAL client.
type Client interface {
	DetectUnfixed(db.DB, *models.ScanResult, bool) (int, error)
	FillCVEsWithRedHat(db.DB, *models.ScanResult) error

	//TODO implement
	// CheckHTTPHealth() error
	// CheckIfGostFetched checks if Gost entries are fetched
	// CheckIfGostFetched(db.DB, string, string) (bool, error)
	// CheckIfGostFresh(db.DB, string, string) (bool, error)
}

// NewClient make Client by family
func NewClient(family string) Client {
	switch family {
	case cnf.RedHat, cnf.CentOS:
		return RedHat{}
	case cnf.Debian:
		return Debian{}
	case cnf.Windows:
		return Microsoft{}
	default:
		return Pseudo{}
	}
}
