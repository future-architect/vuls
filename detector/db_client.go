// +build !scanner

package detector

import (
	"github.com/future-architect/vuls/config"
	metasploitdb "github.com/takuzoo3868/go-msfdb/db"
	"golang.org/x/xerrors"
)

// DBClient is DB client for reporting
type DBClient struct {
	MetasploitDB MetasploitDB
}

// MetasploitDB a DB Client
type MetasploitDB struct {
	DB  metasploitdb.DB
	Cnf config.VulnDictInterface
}

// NewDBClient returns db clients
//TODO remove oval, gost
//TODO remove this func
//TODO Only Validation
func NewDBClient(cveDict, ovalDict, gost, exploit, metasploit config.VulnDictInterface, debugSQL bool) (dbclient *DBClient, err error) {
	metasploitdb, locked, err := NewMetasploitDB(metasploit, debugSQL)
	if locked {
		return nil, xerrors.Errorf("SQLite3 is locked: %s", metasploit.GetSQLite3Path())
	} else if err != nil {
		return nil, err
	}

	return &DBClient{
		MetasploitDB: MetasploitDB{DB: metasploitdb, Cnf: metasploit},
	}, nil
}

// NewMetasploitDB returns db client for Metasploit
func NewMetasploitDB(cnf config.VulnDictInterface, debugSQL bool) (driver metasploitdb.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	if driver, locked, err = metasploitdb.NewDB(cnf.GetType(), path, debugSQL, false); err != nil {
		if locked {
			return nil, true, xerrors.Errorf("metasploitDB is locked. err: %w", err)
		}
		return nil, false, err
	}
	return driver, false, nil
}

// CloseDB close dbs
func (d DBClient) CloseDB() (errs []error) {
	return errs
}
