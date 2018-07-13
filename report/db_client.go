package report

import (
	"fmt"

	"github.com/future-architect/vuls/util"
	gostdb "github.com/knqyf263/gost/db"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	ovaldb "github.com/kotakanbe/goval-dictionary/db"
)

// DBClient is a dictionarie's db client for reporting
type DBClient struct {
	CveDB  cvedb.DB
	OvalDB ovaldb.DB
	GostDB gostdb.DB
}

// DBClientConf has a configuration of Vulnerability DBs
type DBClientConf struct {
	CveDBType string
	CveDBURL  string
	CveDBPath string

	OvalDBType string
	OvalDBURL  string
	OvalDBPath string

	GostDBType string
	GostDBURL  string
	GostDBPath string

	DebugSQL bool
}

// NewDBClient returns db clients
func NewDBClient(cnf DBClientConf) (dbclient *DBClient, locked bool, err error) {
	cveDriver, locked, err := NewCveDB(cnf)
	if err != nil {
		return nil, locked, err
	}

	ovaldb, locked, err := NewOvalDB(cnf)
	if locked {
		return nil, true, fmt.Errorf("OvalDB is locked: %s", cnf.OvalDBPath)
	} else if err != nil {
		util.Log.Warnf("Unable to use OvalDB: %s, err: %s", cnf.OvalDBPath, err)
	}

	gostdb, locked, err := NewGostDB(cnf)
	if locked {
		return nil, true, fmt.Errorf("gostDB is locked: %s", cnf.GostDBPath)
	} else if err != nil {
		util.Log.Warnf("Unable to use gostDB: %s, err: %s", cnf.GostDBPath, err)
	}

	return &DBClient{
		CveDB:  cveDriver,
		OvalDB: ovaldb,
		GostDB: gostdb,
	}, false, nil
}

// NewCveDB returns cve db client
func NewCveDB(cnf DBClientConf) (driver cvedb.DB, locked bool, err error) {
	util.Log.Debugf("open cve-dictionary db (%s)", cnf.CveDBType)
	path := cnf.CveDBURL
	if cnf.CveDBType == "sqlite3" {
		path = cnf.CveDBPath
	}

	util.Log.Debugf("Open cve-dictionary db (%s): %s", cnf.CveDBType, path)
	driver, locked, err = cvedb.NewDB(cnf.CveDBType, path, cnf.DebugSQL)
	if err != nil {
		err = fmt.Errorf("Failed to init CVE DB. err: %s, path: %s", err, path)
		return nil, locked, err
	}
	return driver, false, nil
}

// NewOvalDB returns oval db client
func NewOvalDB(cnf DBClientConf) (driver ovaldb.DB, locked bool, err error) {
	path := cnf.OvalDBURL
	if cnf.OvalDBType == "sqlite3" {
		path = cnf.OvalDBPath
	}

	util.Log.Debugf("Open oval-dictionary db (%s): %s", cnf.OvalDBType, path)
	driver, locked, err = ovaldb.NewDB("", cnf.OvalDBType, path, cnf.DebugSQL)
	if err != nil {
		err = fmt.Errorf("Failed to new OVAL DB. err: %s", err)
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}
	return driver, false, nil
}

// NewGostDB returns db client for Gost
func NewGostDB(cnf DBClientConf) (driver gostdb.DB, locked bool, err error) {
	path := cnf.GostDBURL
	if cnf.GostDBType == "sqlite3" {
		path = cnf.GostDBPath
	}

	util.Log.Debugf("Open gost db (%s): %s", cnf.GostDBType, path)
	if driver, locked, err = gostdb.NewDB(cnf.GostDBType, path, cnf.DebugSQL); err != nil {
		if locked {
			util.Log.Debugf("gostDB is locked: %s, %T", err, err)
			return nil, true, err
		}
		return nil, false, err
	}
	return driver, false, nil
}

// CloseDB close dbs
func (d DBClient) CloseDB() {
	if d.CveDB != nil {
		if err := d.CveDB.CloseDB(); err != nil {
			util.Log.Errorf("Failed to close DB: %s", err)
		}
	}
	if d.OvalDB != nil {
		if err := d.OvalDB.CloseDB(); err != nil {
			util.Log.Errorf("Failed to close DB: %s", err)
		}
	}
}
