package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

// GovalDictConf is goval-dictionary config
type GovalDictConf struct {

	// DB type of OVAL dictionary (sqlite3, mysql, postgres or redis)
	Type string

	// http://goval-dictionary.com:1324 or DB connection string
	URL string `json:"-"`

	// /path/to/oval.sqlite3
	SQLite3Path string `json:"-"`
}

func (cnf *GovalDictConf) setDefault() {
	if cnf.Type == "" {
		cnf.Type = "sqlite3"
	}
	if cnf.URL == "" && cnf.SQLite3Path == "" {
		wd, _ := os.Getwd()
		cnf.SQLite3Path = filepath.Join(wd, "oval.sqlite3")
	}
}

const govalType = "OVALDB_TYPE"
const govalURL = "OVALDB_URL"
const govalPATH = "OVALDB_SQLITE3_PATH"

// Init set options with the following priority.
// 1. Environment variable
// 2. config.toml
func (cnf *GovalDictConf) Init() {
	if os.Getenv(govalType) != "" {
		cnf.Type = os.Getenv(govalType)
	}
	if os.Getenv(govalURL) != "" {
		cnf.URL = os.Getenv(govalURL)
	}
	if os.Getenv(govalPATH) != "" {
		cnf.SQLite3Path = os.Getenv(govalPATH)
	}
	cnf.setDefault()
}

// IsFetchViaHTTP returns wether fetch via http
func (cnf *GovalDictConf) IsFetchViaHTTP() bool {
	return Conf.OvalDict.Type == "http"
}

// CheckHTTPHealth do health check
func (cnf *GovalDictConf) CheckHTTPHealth() error {
	if !cnf.IsFetchViaHTTP() {
		return nil
	}

	url := fmt.Sprintf("%s/health", cnf.URL)
	resp, _, errs := gorequest.New().Timeout(10 * time.Second).Get(url).End()
	//  resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return xerrors.Errorf("Failed to request to OVAL server. url: %s, errs: %s",
			url, errs)
	}
	return nil
}
