package report

import (
	"fmt"

	"github.com/future-architect/vuls/util"
	gostdb "github.com/knqyf263/gost/db"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	ovaldb "github.com/kotakanbe/goval-dictionary/db"
	log "github.com/sirupsen/logrus"
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
func NewDBClient(cnf DBClientConf) (dbclient DBClient, err error) {
	var cveDriver cvedb.DB
	if cveDriver, err = NewCveDB(cnf); err != nil {
		return DBClient{}, fmt.Errorf("Failed to New DB Client. err: %s", err)
	}
	return DBClient{
		CveDB:  cveDriver,
		OvalDB: NewOvalDB(cnf),
		GostDB: NewGostDB(cnf),
	}, nil
}

// NewCveDB returns cve db client
func NewCveDB(cnf DBClientConf) (driver cvedb.DB, err error) {
	util.Log.Debugf("open cve-dictionary db (%s)", cnf.CveDBType)
	path := cnf.CveDBURL
	if cnf.CveDBType == "sqlite3" {
		path = cnf.CveDBPath
	}

	util.Log.Debugf("Open cve-dictionary db (%s): %s",
		cnf.CveDBType, path)
	if driver, err = cvedb.NewDB(cnf.CveDBType, path, cnf.DebugSQL); err != nil {
		log.Error(err)
		return nil, fmt.Errorf("Failed to New Cve DB. err: %s", err)
	}

	return driver, nil
}

// NewOvalDB returns oval db client
func NewOvalDB(cnf DBClientConf) (driver ovaldb.DB) {
	var err error
	path := cnf.OvalDBPath
	if cnf.OvalDBType == "sqlite3" {
		path = cnf.OvalDBPath
	}

	util.Log.Debugf("Open oval-dictionary db (%s): %s",
		cnf.OvalDBType, path)

	if driver, err = ovaldb.NewDB("", cnf.OvalDBType, path, cnf.DebugSQL); err != nil {
		util.Log.Debugf("oval-dictionary db is not detected")
		return nil
	}
	return driver
}

// NewGostDB returns db client for Gost
func NewGostDB(cnf DBClientConf) (driver gostdb.DB) {
	var err error
	path := cnf.GostDBPath
	if cnf.GostDBType == "sqlite3" {
		path = cnf.GostDBPath
	}

	util.Log.Debugf("Open gost db (%s): %s", cnf.GostDBType, path)
	if driver, err = gostdb.NewDB(cnf.GostDBType, path, cnf.DebugSQL); err != nil {
		util.Log.Debugf("oval-dictionary db is not detected")
		return nil
	}
	return driver
}

// CloseDB close dbs
func (d DBClient) CloseDB() {
	if err := d.OvalDB.CloseDB(); err != nil {
		util.Log.Errorf("Failed to close DB: %s", err)
	}
	if err := d.CveDB.CloseDB(); err != nil {
		util.Log.Errorf("Failed to close DB: %s", err)
	}
}
