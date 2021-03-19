// +build !scanner

package detector

import (
	"github.com/future-architect/vuls/config"
	metasploitdb "github.com/takuzoo3868/go-msfdb/db"
	exploitdb "github.com/vulsio/go-exploitdb/db"
	"golang.org/x/xerrors"
)

// DBClient is DB client for reporting
type DBClient struct {
	ExploitDB    ExploitDB
	MetasploitDB MetasploitDB
}

// ExploitDB is a DB Client
type ExploitDB struct {
	DB  exploitdb.DB
	Cnf config.VulnDictInterface
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
	exploitdb, locked, err := NewExploitDB(exploit, debugSQL)
	if locked {
		return nil, xerrors.Errorf("SQLite3 is locked: %s", exploit.GetSQLite3Path())
	} else if err != nil {
		return nil, err
	}

	metasploitdb, locked, err := NewMetasploitDB(metasploit, debugSQL)
	if locked {
		return nil, xerrors.Errorf("SQLite3 is locked: %s", metasploit.GetSQLite3Path())
	} else if err != nil {
		return nil, err
	}

	return &DBClient{
		ExploitDB:    ExploitDB{DB: exploitdb, Cnf: exploit},
		MetasploitDB: MetasploitDB{DB: metasploitdb, Cnf: metasploit},
	}, nil
}

// NewExploitDB returns db client for Exploit
func NewExploitDB(cnf config.VulnDictInterface, debugSQL bool) (driver exploitdb.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	if driver, locked, err = exploitdb.NewDB(cnf.GetType(), path, debugSQL); err != nil {
		if locked {
			return nil, true, xerrors.Errorf("exploitDB is locked. err: %w", err)
		}
		return nil, false, err
	}
	return driver, false, nil
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
