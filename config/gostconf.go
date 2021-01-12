package config

import (
	"os"
	"path/filepath"
)

// GostConf is gost config
type GostConf struct {
	// DB type for gost dictionary (sqlite3, mysql, postgres or redis)
	Type string

	// http://gost-dictionary.com:1324 or DB connection string
	URL string `json:"-"`

	// /path/to/gost.sqlite3
	SQLite3Path string `json:"-"`
}

func (cnf *GostConf) setDefault() {
	if cnf.Type == "" {
		cnf.Type = "sqlite3"
	}
	if cnf.URL == "" && cnf.SQLite3Path == "" {
		wd, _ := os.Getwd()
		cnf.SQLite3Path = filepath.Join(wd, "gost.sqlite3")
	}
}

const gostDBType = "GOSTDB_TYPE"
const gostDBURL = "GOSTDB_URL"
const gostDBPATH = "GOSTDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *GostConf) Init() {
	if os.Getenv(gostDBType) != "" {
		cnf.Type = os.Getenv(gostDBType)
	}
	if os.Getenv(gostDBURL) != "" {
		cnf.URL = os.Getenv(gostDBURL)
	}
	if os.Getenv(gostDBPATH) != "" {
		cnf.SQLite3Path = os.Getenv(gostDBPATH)
	}
	cnf.setDefault()
}

// IsFetchViaHTTP returns wether fetch via http
func (cnf *GostConf) IsFetchViaHTTP() bool {
	return Conf.Gost.Type == "http"
}
