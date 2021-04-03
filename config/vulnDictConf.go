package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/future-architect/vuls/logging"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

// VulnDictInterface is an interface of vulnsrc
type VulnDictInterface interface {
	Init()
	Validate() error
	IsFetchViaHTTP() bool
	CheckHTTPHealth() error
	GetName() string
	GetType() string
	GetURL() string
	GetSQLite3Path() string
	GetDebugSQL() bool
}

// VulnDict is a base struct of vuln dicts
type VulnDict struct {
	Name string

	// DB type of CVE dictionary (sqlite3, mysql, postgres or redis)
	Type string

	// http://cve-dictionary.com:1323 or DB connection string
	URL string `json:"-"`

	// /path/to/cve.sqlite3
	SQLite3Path string

	DebugSQL bool
}

// GetType returns type
func (cnf VulnDict) GetType() string {
	return cnf.Type
}

// GetName returns name
func (cnf VulnDict) GetName() string {
	return cnf.Name
}

// GetURL returns url
func (cnf VulnDict) GetURL() string {
	return cnf.URL
}

// GetSQLite3Path return the path of SQLite3
func (cnf VulnDict) GetSQLite3Path() string {
	return cnf.SQLite3Path
}

// GetDebugSQL return debugSQL flag
func (cnf VulnDict) GetDebugSQL() bool {
	return cnf.DebugSQL
}

// Validate settings
func (cnf VulnDict) Validate() error {
	logging.Log.Infof("%s.type=%s, %s.url=%s, %s.SQLite3Path=%s",
		cnf.Name, cnf.Type, cnf.Name, cnf.URL, cnf.Name, cnf.SQLite3Path)

	switch cnf.Type {
	case "sqlite3":
		if cnf.URL != "" {
			return xerrors.Errorf("To use SQLite3, specify %s.type=sqlite3 and %s.SQLite3Path. To use as HTTP server mode, specify %s.type=http and %s.url",
				cnf.Name, cnf.Name, cnf.Name, cnf.Name)
		}
		if ok, _ := govalidator.IsFilePath(cnf.SQLite3Path); !ok {
			return xerrors.Errorf("SQLite3 path must be a *Absolute* file path. %s.SQLite3Path: %s",
				cnf.Name, cnf.SQLite3Path)
		}
		if _, err := os.Stat(cnf.SQLite3Path); os.IsNotExist(err) {
			logging.Log.Warnf("%s.SQLite3Path=%s file not found", cnf.Name, cnf.SQLite3Path)
		}
	case "mysql":
		if cnf.URL == "" {
			return xerrors.Errorf(`MySQL connection string is needed. %s.url="user:pass@tcp(localhost:3306)/dbname"`, cnf.Name)
		}
	case "postgres":
		if cnf.URL == "" {
			return xerrors.Errorf(`PostgreSQL connection string is needed. %s.url="host=myhost user=user dbname=dbname sslmode=disable password=password"`, cnf.Name)
		}
	case "redis":
		if cnf.URL == "" {
			return xerrors.Errorf(`Redis connection string is needed. %s.url="redis://localhost/0"`, cnf.Name)
		}
	case "http":
		if cnf.URL == "" {
			return xerrors.Errorf(`URL is needed. -%s-url="http://localhost:1323"`, cnf.Name)
		}
	default:
		return xerrors.Errorf("%s.type must be either 'sqlite3', 'mysql', 'postgres', 'redis' or 'http'.  %s.type: %s", cnf.Name, cnf.Name, cnf.Type)
	}
	return nil
}

// Init the struct
func (cnf VulnDict) Init() {}

func (cnf *VulnDict) setDefault(sqlite3Name string) {
	if cnf.Type == "" {
		cnf.Type = "sqlite3"
	}
	if cnf.URL == "" && cnf.SQLite3Path == "" {
		wd, _ := os.Getwd()
		cnf.SQLite3Path = filepath.Join(wd, sqlite3Name)
	}
}

// IsFetchViaHTTP returns if fetch via HTTP
func (cnf VulnDict) IsFetchViaHTTP() bool {
	return cnf.Type == "http"
}

// CheckHTTPHealth checks http server status
func (cnf VulnDict) CheckHTTPHealth() error {
	if !cnf.IsFetchViaHTTP() {
		return nil
	}

	url := fmt.Sprintf("%s/health", cnf.URL)
	resp, _, errs := gorequest.New().Timeout(10 * time.Second).SetDebug(Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return xerrors.Errorf("Failed to request to CVE server. url: %s, errs: %s",
			url, errs)
	}
	return nil
}

// GovalDictConf is goval-dictionary config
type GovalDictConf struct {
	VulnDict
}

const govalType = "OVALDB_TYPE"
const govalURL = "OVALDB_URL"
const govalPATH = "OVALDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *GovalDictConf) Init() {
	cnf.Name = "ovalDict"
	if os.Getenv(govalType) != "" {
		cnf.Type = os.Getenv(govalType)
	}
	if os.Getenv(govalURL) != "" {
		cnf.URL = os.Getenv(govalURL)
	}
	if os.Getenv(govalPATH) != "" {
		cnf.SQLite3Path = os.Getenv(govalPATH)
	}
	cnf.setDefault("oval.sqlite3")
	cnf.DebugSQL = Conf.DebugSQL
}

// ExploitConf is exploit config
type ExploitConf struct {
	VulnDict
}

const exploitDBType = "EXPLOITDB_TYPE"
const exploitDBURL = "EXPLOITDB_URL"
const exploitDBPATH = "EXPLOITDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *ExploitConf) Init() {
	cnf.Name = "exploit"
	if os.Getenv(exploitDBType) != "" {
		cnf.Type = os.Getenv(exploitDBType)
	}
	if os.Getenv(exploitDBURL) != "" {
		cnf.URL = os.Getenv(exploitDBURL)
	}
	if os.Getenv(exploitDBPATH) != "" {
		cnf.SQLite3Path = os.Getenv(exploitDBPATH)
	}
	cnf.setDefault("go-exploitdb.sqlite3")
	cnf.DebugSQL = Conf.DebugSQL
}

// GoCveDictConf is GoCveDict config
type GoCveDictConf struct {
	VulnDict
}

const cveDBType = "CVEDB_TYPE"
const cveDBURL = "CVEDB_URL"
const cveDBPATH = "CVEDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *GoCveDictConf) Init() {
	cnf.Name = "cveDict"
	if os.Getenv(cveDBType) != "" {
		cnf.Type = os.Getenv(cveDBType)
	}
	if os.Getenv(cveDBURL) != "" {
		cnf.URL = os.Getenv(cveDBURL)
	}
	if os.Getenv(cveDBPATH) != "" {
		cnf.SQLite3Path = os.Getenv(cveDBPATH)
	}
	cnf.setDefault("cve.sqlite3")
	cnf.DebugSQL = Conf.DebugSQL
}

// GostConf is gost config
type GostConf struct {
	VulnDict
}

const gostDBType = "GOSTDB_TYPE"
const gostDBURL = "GOSTDB_URL"
const gostDBPATH = "GOSTDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *GostConf) Init() {
	cnf.Name = "gost"
	if os.Getenv(gostDBType) != "" {
		cnf.Type = os.Getenv(gostDBType)
	}
	if os.Getenv(gostDBURL) != "" {
		cnf.URL = os.Getenv(gostDBURL)
	}
	if os.Getenv(gostDBPATH) != "" {
		cnf.SQLite3Path = os.Getenv(gostDBPATH)
	}
	cnf.setDefault("gost.sqlite3")
	cnf.DebugSQL = Conf.DebugSQL
}

// MetasploitConf is gost go-metasploitdb
type MetasploitConf struct {
	VulnDict
}

const metasploitDBType = "METASPLOITDB_TYPE"
const metasploitDBURL = "METASPLOITDB_URL"
const metasploitDBPATH = "METASPLOITDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *MetasploitConf) Init() {
	cnf.Name = "metasploit"
	if os.Getenv(metasploitDBType) != "" {
		cnf.Type = os.Getenv(metasploitDBType)
	}
	if os.Getenv(metasploitDBURL) != "" {
		cnf.URL = os.Getenv(metasploitDBURL)
	}
	if os.Getenv(metasploitDBPATH) != "" {
		cnf.SQLite3Path = os.Getenv(metasploitDBPATH)
	}
	cnf.setDefault("go-msfdb.sqlite3")
	cnf.DebugSQL = Conf.DebugSQL
}
