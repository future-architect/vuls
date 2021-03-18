// +build !scanner

package gost

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/constant"
)

// DB is a DB Client
type DBDriver struct {
	DB  db.DB
	Cnf config.VulnDictInterface
}

// Client is the interface of OVAL client.
type Client interface {
	DetectUnfixed(*models.ScanResult, bool) (int, error)
}

// Base is a base struct
type Base struct {
	DBDriver DBDriver
}

func FillCVEsWithRedHat(r *models.ScanResult, cnf config.GostConf) error {
	db, locked, err := newGostDB(cnf)
	if locked {
		return xerrors.Errorf("SQLite3 is locked: %s", cnf.GetSQLite3Path())
	} else if err != nil {
		return err
	}
	//TODO closeDB
	return RedHat{Base{DBDriver{DB: db, Cnf: &cnf}}}.fillCvesWithRedHatAPI(r)
}

// NewClient make Client by family
//TODO move debugSQL to VulnDictInterface
func NewClient(cnf config.GostConf, family string) (Client, error) {
	db, locked, err := newGostDB(cnf)
	if locked {
		return nil, xerrors.Errorf("SQLite3 is locked: %s", cnf.GetSQLite3Path())
	} else if err != nil {
		return nil, err
	}

	driver := DBDriver{DB: db, Cnf: &cnf}

	switch family {
	case constant.RedHat, constant.CentOS:
		return RedHat{Base{DBDriver: driver}}, nil
	case constant.Debian, constant.Raspbian:
		return Debian{Base{DBDriver: driver}}, nil
	case constant.Windows:
		return Microsoft{Base{DBDriver: driver}}, nil
	default:
		return Pseudo{}, nil
	}
}

// NewGostDB returns db client for Gost
func newGostDB(cnf config.GostConf) (driver db.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	if driver, locked, err = db.NewDB(cnf.GetType(), path, cnf.GetDebugSQL()); err != nil {
		if locked {
			return nil, true, xerrors.Errorf("gostDB is locked. err: %w", err)
		}
		return nil, false, err
	}
	return driver, false, nil
}
