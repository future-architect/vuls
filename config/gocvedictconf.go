package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

// GoCveDictConf is go-cve-dictionary config
type GoCveDictConf struct {
	// DB type of CVE dictionary (sqlite3, mysql, postgres or redis)
	Type string

	// http://cve-dictionary.com:1323 or DB connection string
	URL string `json:"-"`

	// /path/to/cve.sqlite3
	SQLite3Path string `json:"-"`
}

func (cnf *GoCveDictConf) setDefault() {
	if cnf.Type == "" {
		cnf.Type = "sqlite3"
	}
	if cnf.URL == "" && cnf.SQLite3Path == "" {
		wd, _ := os.Getwd()
		cnf.SQLite3Path = filepath.Join(wd, "cve.sqlite3")
	}
}

const cveDBType = "CVEDB_TYPE"
const cveDBURL = "CVEDB_URL"
const cveDBPATH = "CVEDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *GoCveDictConf) Init() {
	if os.Getenv(cveDBType) != "" {
		cnf.Type = os.Getenv(cveDBType)
	}
	if os.Getenv(cveDBURL) != "" {
		cnf.URL = os.Getenv(cveDBURL)
	}
	if os.Getenv(cveDBPATH) != "" {
		cnf.SQLite3Path = os.Getenv(cveDBPATH)
	}
	cnf.setDefault()
}

// IsFetchViaHTTP returns wether fetch via http
func (cnf *GoCveDictConf) IsFetchViaHTTP() bool {
	return Conf.CveDict.Type == "http"
}

// CheckHTTPHealth checks http server status
func (cnf *GoCveDictConf) CheckHTTPHealth() error {
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
