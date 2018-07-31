package report

import (
	"fmt"
	"os"

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

func (c DBClientConf) isCveDBViaHTTP() bool {
	return c.CveDBURL != "" && c.CveDBType == "sqlite3"
}

func (c DBClientConf) isOvalViaHTTP() bool {
	return c.OvalDBURL != "" && c.OvalDBType == "sqlite3"
}

func (c DBClientConf) isGostViaHTTP() bool {
	return c.GostDBURL != "" && c.GostDBType == "sqlite3"
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
	if cnf.isCveDBViaHTTP() {
		return nil, false, nil
	}
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
	if cnf.isOvalViaHTTP() {
		return nil, false, nil
	}
	path := cnf.OvalDBURL
	if cnf.OvalDBType == "sqlite3" {
		path = cnf.OvalDBPath

		if _, err := os.Stat(path); os.IsNotExist(err) {
			util.Log.Warnf("--ovaldb-path=%s is not found. It's recommended to use OVAL to improve scanning accuracy. For details, see https://github.com/kotakanbe/goval-dictionary#usage", path)
			return nil, false, nil
		}
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
	if cnf.isGostViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GostDBURL
	if cnf.GostDBType == "sqlite3" {
		path = cnf.GostDBPath

		if _, err := os.Stat(path); os.IsNotExist(err) {
			util.Log.Warnf("--gostdb-path=%s is not found. If the scan target server is Debian, RHEL or CentOS, it's recommended to use gost to improve scanning accuracy. To use gost database, see https://github.com/knqyf263/gost#fetch-redhat", path)
			return nil, false, nil
		}
	}

	util.Log.Debugf("Open gost db (%s): %s", cnf.GostDBType, path)
	if driver, locked, err = gostdb.NewDB(cnf.GostDBType, path, cnf.DebugSQL); err != nil {
		if locked {
			util.Log.Errorf("gostDB is locked: %s", err)
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
