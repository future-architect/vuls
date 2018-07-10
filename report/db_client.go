package report

import (
	"fmt"

	"github.com/future-architect/vuls/util"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	ovaldb "github.com/kotakanbe/goval-dictionary/db"
	log "github.com/sirupsen/logrus"
)

// DBClient is a dictionarie's db client for reporting
type DBClient struct {
	CveDB  cvedb.DB
	OvalDB ovaldb.DB
}

// NewDBClient returns db clients
func NewDBClient(cType, cURL, cPath, oType, oURL, oPath string, debug bool) (dbclient DBClient, err error) {
	var cveDriver cvedb.DB
	if cveDriver, err = NewCveDB(cType, cURL, cPath, debug); err != nil {
		return DBClient{}, fmt.Errorf("Failed to New DB Client. err: %s", err)
	}
	return DBClient{
		CveDB:  cveDriver,
		OvalDB: NewOvalDB(oType, oURL, oPath, debug),
	}, nil
}

// NewCveDB returns cve db client
func NewCveDB(cType, cURL, cPath string, debug bool) (driver cvedb.DB, err error) {
	util.Log.Debugf("open cve-dictionary db (%s)", cType)
	path := cURL
	if cType == "sqlite3" {
		path = cPath
	}

	util.Log.Debugf("Open cve-dictionary db (%s): %s", cType, path)
	if driver, _, err = cvedb.NewDB(cType, path, debug); err != nil {
		log.Error(err)
		return nil, fmt.Errorf("Failed to New Cve DB. err: %s", err)
	}

	return driver, nil
}

// NewOvalDB returns oval db client
func NewOvalDB(oType, oURL, oPath string, debug bool) (driver ovaldb.DB) {
	var err error
	path := oURL
	if oType == "sqlite3" {
		path = oPath
	}

	util.Log.Debugf("Open oval-dictionary db (%s): %s", oType, path)
	if driver, _, err = ovaldb.NewDB("", oType, path, debug); err != nil {
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
