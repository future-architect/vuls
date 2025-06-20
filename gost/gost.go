//go:build !scanner

package gost

import (
	"errors"

	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	gostdb "github.com/vulsio/gost/db"
	gostlog "github.com/vulsio/gost/util"
)

// Client is the interface of Gost client.
type Client interface {
	DetectCVEs(*models.ScanResult, bool) (int, error)
	CloseDB() error
}

// Base is a base struct
type Base struct {
	driver  gostdb.DB
	baseURL string
}

// CloseDB close a DB connection
func (b Base) CloseDB() error {
	if b.driver == nil {
		return nil
	}
	return b.driver.CloseDB()
}

// FillCVEsWithRedHat fills CVE detailed with Red Hat Security
func FillCVEsWithRedHat(r *models.ScanResult, cnf config.GostConf, o logging.LogOpts) error {
	if err := gostlog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return err
	}

	db, err := newGostDB(&cnf)
	if err != nil {
		return xerrors.Errorf("Failed to newGostDB. err: %w", err)
	}

	client := RedHat{Base{driver: db, baseURL: cnf.GetURL()}}
	defer func() {
		if err := client.CloseDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()
	return client.fillCvesWithRedHatAPI(r)
}

// NewGostClient make Client by family
func NewGostClient(cnf config.GostConf, family string, o logging.LogOpts) (Client, error) {
	if err := gostlog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return nil, xerrors.Errorf("Failed to set gost logger. err: %w", err)
	}

	db, err := newGostDB(&cnf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to newGostDB. err: %w", err)
	}

	base := Base{driver: db, baseURL: cnf.GetURL()}
	switch family {
	case constant.Debian, constant.Raspbian:
		return Debian{base}, nil
	case constant.Ubuntu:
		return Ubuntu{base}, nil
	case constant.Windows:
		return Microsoft{base}, nil
	case constant.ServerTypePseudo:
		return Pseudo{base}, nil
	default:
		if family == "" {
			return nil, xerrors.New("Probably an error occurred during scanning. Check the error message")
		}
		return nil, xerrors.Errorf("Gost for %s is not implemented yet", family)
	}
}

// NewGostDB returns db client for Gost
func newGostDB(cnf config.VulnDictInterface) (gostdb.DB, error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, err := gostdb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), gostdb.Option{})
	if err != nil {
		if errors.Is(err, gostdb.ErrDBLocked) {
			return nil, xerrors.Errorf("Failed to init gost DB. SQLite3: %s is locked. err: %w", cnf.GetSQLite3Path(), err)
		}
		return nil, xerrors.Errorf("Failed to init gost DB. DB Path: %s, err: %w", path, err)
	}
	return driver, nil
}
