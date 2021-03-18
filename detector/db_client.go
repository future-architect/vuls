// +build !scanner

package detector

import (
	"github.com/future-architect/vuls/config"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	metasploitdb "github.com/takuzoo3868/go-msfdb/db"
	exploitdb "github.com/vulsio/go-exploitdb/db"
	"golang.org/x/xerrors"
)

// DBClient is DB client for reporting
type DBClient struct {
	CveDB        CveDB
	ExploitDB    ExploitDB
	MetasploitDB MetasploitDB
}

// CveDB is a DB client
type CveDB struct {
	DB  cvedb.DB
	Cnf config.VulnDictInterface
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
	for _, cnf := range []config.VulnDictInterface{cveDict, ovalDict, gost, exploit, metasploit} {
		if err := cnf.Validate(); err != nil {
			return nil, xerrors.Errorf("Failed to validate %s: %+v", cnf.GetName(), err)
		}
		if err := cnf.CheckHTTPHealth(); err != nil {
			return nil, xerrors.Errorf("Run %s as server mode before reporting: %+v", cnf.GetName(), err)
		}
	}

	// cveDB, locked, err := NewCveDB(cveDict, debugSQL)
	// if locked {
	// 	return nil, xerrors.Errorf("SQLite3 is locked: %s", cveDict.GetSQLite3Path())
	// } else if err != nil {
	// 	return nil, err
	// }

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
		// CveDB: CveDB{DB: cveDB, Cnf: cveDict},
		// OvalDB:       OvalDB{DB: ovaldb, Cnf: ovalDict},
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
	// if d.CveDB.DB != nil {
	// 	if err := d.CveDB.DB.CloseDB(); err != nil {
	// 		errs = append(errs, xerrors.Errorf("Failed to close cveDB. err: %+v", err))
	// 	}
	// }
	//TODO CloseDB gost, exploitdb, metasploit
	return errs
}
