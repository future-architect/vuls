package report

import (
	"os"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/util"
	gostdb "github.com/knqyf263/gost/db"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	ovaldb "github.com/kotakanbe/goval-dictionary/db"
	exploitdb "github.com/mozqnet/go-exploitdb/db"
	"golang.org/x/xerrors"
)

// DBClient is a dictionarie's db client for reporting
type DBClient struct {
	CveDB     cvedb.DB
	OvalDB    ovaldb.DB
	GostDB    gostdb.DB
	ExploitDB exploitdb.DB
}

// DBClientConf has a configuration of Vulnerability DBs
type DBClientConf struct {
	CveDictCnf  config.GoCveDictConf
	OvalDictCnf config.GovalDictConf
	GostCnf     config.GostConf
	ExploitCnf  config.ExploitConf
	DebugSQL    bool
}

// NewDBClient returns db clients
func NewDBClient(cnf DBClientConf) (dbclient *DBClient, locked bool, err error) {
	cveDriver, locked, err := NewCveDB(cnf)
	if locked {
		return nil, true, xerrors.Errorf("CveDB is locked: %s",
			cnf.OvalDictCnf.SQLite3Path)
	} else if err != nil {
		return nil, locked, err
	}

	ovaldb, locked, err := NewOvalDB(cnf)
	if locked {
		return nil, true, xerrors.Errorf("OvalDB is locked: %s",
			cnf.OvalDictCnf.SQLite3Path)
	} else if err != nil {
		util.Log.Warnf("Unable to use OvalDB: %s, err: %s",
			cnf.OvalDictCnf.SQLite3Path, err)
	}

	gostdb, locked, err := NewGostDB(cnf)
	if locked {
		return nil, true, xerrors.Errorf("gostDB is locked: %s",
			cnf.GostCnf.SQLite3Path)
	} else if err != nil {
		util.Log.Warnf("Unable to use gostDB: %s, err: %s",
			cnf.GostCnf.SQLite3Path, err)
	}

	exploitdb, locked, err := NewExploitDB(cnf)
	if locked {
		return nil, true, xerrors.Errorf("exploitDB is locked: %s",
			cnf.ExploitCnf.SQLite3Path)
	} else if err != nil {
		util.Log.Warnf("Unable to use exploitDB: %s, err: %s",
			cnf.ExploitCnf.SQLite3Path, err)
	}

	return &DBClient{
		CveDB:     cveDriver,
		OvalDB:    ovaldb,
		GostDB:    gostdb,
		ExploitDB: exploitdb,
	}, false, nil
}

// NewCveDB returns cve db client
func NewCveDB(cnf DBClientConf) (driver cvedb.DB, locked bool, err error) {
	if config.Conf.CveDict.IsFetchViaHTTP() {
		return nil, false, nil
	}
	util.Log.Debugf("open cve-dictionary db (%s)", cnf.CveDictCnf.Type)
	path := cnf.CveDictCnf.URL
	if cnf.CveDictCnf.Type == "sqlite3" {
		path = cnf.CveDictCnf.SQLite3Path
	}

	util.Log.Debugf("Open cve-dictionary db (%s): %s", cnf.CveDictCnf.Type, path)
	driver, locked, err = cvedb.NewDB(cnf.CveDictCnf.Type, path, cnf.DebugSQL)
	if err != nil {
		err = xerrors.Errorf("Failed to init CVE DB. err: %w, path: %s", err, path)
		return nil, locked, err
	}
	return driver, false, nil
}

// NewOvalDB returns oval db client
func NewOvalDB(cnf DBClientConf) (driver ovaldb.DB, locked bool, err error) {
	if config.Conf.OvalDict.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.OvalDictCnf.URL
	if cnf.OvalDictCnf.Type == "sqlite3" {
		path = cnf.OvalDictCnf.SQLite3Path

		if _, err := os.Stat(path); os.IsNotExist(err) {
			util.Log.Warnf("--ovaldb-path=%s is not found. It's recommended to use OVAL to improve scanning accuracy. For details, see https://github.com/kotakanbe/goval-dictionary#usage", path)
			return nil, false, nil
		}
	}

	util.Log.Debugf("Open oval-dictionary db (%s): %s", cnf.OvalDictCnf.Type, path)
	driver, locked, err = ovaldb.NewDB("", cnf.OvalDictCnf.Type, path, cnf.DebugSQL)
	if err != nil {
		err = xerrors.Errorf("Failed to new OVAL DB. err: %w", err)
		if locked {
			return nil, true, err
		}
		return nil, false, err
	}
	return driver, false, nil
}

// NewGostDB returns db client for Gost
func NewGostDB(cnf DBClientConf) (driver gostdb.DB, locked bool, err error) {
	if config.Conf.Gost.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GostCnf.URL
	if cnf.GostCnf.Type == "sqlite3" {
		path = cnf.GostCnf.SQLite3Path

		if _, err := os.Stat(path); os.IsNotExist(err) {
			util.Log.Warnf("--gostdb-path=%s is not found. If the scan target server is Debian, RHEL or CentOS, it's recommended to use gost to improve scanning accuracy. To use gost database, see https://github.com/knqyf263/gost#fetch-redhat", path)
			return nil, false, nil
		}
	}

	util.Log.Debugf("Open gost db (%s): %s", cnf.GostCnf.Type, path)
	if driver, locked, err = gostdb.NewDB(cnf.GostCnf.Type, path, cnf.DebugSQL); err != nil {
		if locked {
			util.Log.Errorf("gostDB is locked. err: %+v", err)
			return nil, true, err
		}
		return nil, false, err
	}
	return driver, false, nil
}

// NewExploitDB returns db client for Exploit
func NewExploitDB(cnf DBClientConf) (driver exploitdb.DB, locked bool, err error) {
	if config.Conf.Exploit.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.ExploitCnf.URL
	if cnf.ExploitCnf.Type == "sqlite3" {
		path = cnf.ExploitCnf.SQLite3Path

		if _, err := os.Stat(path); os.IsNotExist(err) {
			util.Log.Warnf("--exploitdb-path=%s is not found. It's recommended to use exploit to improve scanning accuracy. To use exploit db database, see https://github.com/mozqnet/go-exploitdb", path)
			return nil, false, nil
		}
	}

	util.Log.Debugf("Open exploit db (%s): %s", cnf.ExploitCnf.Type, path)
	if driver, locked, err = exploitdb.NewDB(cnf.ExploitCnf.Type, path, cnf.DebugSQL); err != nil {
		if locked {
			util.Log.Errorf("exploitDB is locked. err: %+v", err)
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
			util.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}
	if d.OvalDB != nil {
		if err := d.OvalDB.CloseDB(); err != nil {
			util.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}
}
