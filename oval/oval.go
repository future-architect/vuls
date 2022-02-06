//go:build !scanner
// +build !scanner

package oval

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ovaldb "github.com/vulsio/goval-dictionary/db"
)

// Client is the interface of OVAL client.
type Client interface {
	FillWithOval(*models.ScanResult) (int, error)
	CheckIfOvalFetched(string, string) (bool, error)
	CheckIfOvalFresh(string, string) (bool, error)
	CloseDB() error
}

// Base is a base struct
type Base struct {
	driver  ovaldb.DB
	baseURL string
	family  string
}

// CloseDB close a DB connection
func (b Base) CloseDB() error {
	if b.driver == nil {
		return nil
	}
	return b.driver.CloseDB()
}

// CheckIfOvalFetched checks if oval entries are in DB by family, release.
func (b Base) CheckIfOvalFetched(osFamily, release string) (bool, error) {
	ovalFamily, err := GetFamilyInOval(osFamily)
	if err != nil {
		return false, xerrors.Errorf("Failed to GetFamilyInOval. err: %w", err)
	}
	ovalRelease := release
	if osFamily == constant.CentOS {
		ovalRelease = strings.TrimPrefix(release, "stream")
	}

	var count int
	if b.driver == nil {
		url, err := util.URLPathJoin(b.baseURL, "count", ovalFamily, ovalRelease)
		if err != nil {
			return false, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}
		resp, body, errs := gorequest.New().Timeout(10 * time.Second).Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return false, xerrors.Errorf("HTTP GET error, url: %s, resp: %v, err: %+v", url, resp, errs)
		}
		if err := json.Unmarshal([]byte(body), &count); err != nil {
			return false, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
	} else {
		count, err = b.driver.CountDefs(ovalFamily, ovalRelease)
		if err != nil {
			return false, xerrors.Errorf("Failed to count OVAL defs: %s, %s, %w", ovalFamily, ovalRelease, err)
		}
	}
	logging.Log.Infof("OVAL %s %s found. defs: %d", ovalFamily, ovalRelease, count)
	return 0 < count, nil
}

// CheckIfOvalFresh checks if oval entries are fresh enough
func (b Base) CheckIfOvalFresh(osFamily, release string) (ok bool, err error) {
	ovalFamily, err := GetFamilyInOval(osFamily)
	if err != nil {
		return false, xerrors.Errorf("Failed to GetFamilyInOval. err: %w", err)
	}
	ovalRelease := release
	if osFamily == constant.CentOS {
		ovalRelease = strings.TrimPrefix(release, "stream")
	}

	var lastModified time.Time
	if b.driver == nil {
		url, err := util.URLPathJoin(b.baseURL, "lastmodified", ovalFamily, ovalRelease)
		if err != nil {
			return false, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}
		resp, body, errs := gorequest.New().Timeout(10 * time.Second).Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return false, xerrors.Errorf("HTTP GET error, url: %s, resp: %v, err: %+v", url, resp, errs)
		}
		if err := json.Unmarshal([]byte(body), &lastModified); err != nil {
			return false, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
	} else {
		lastModified, err = b.driver.GetLastModified(ovalFamily, ovalRelease)
		if err != nil {
			return false, xerrors.Errorf("Failed to GetLastModified: %w", err)
		}
	}

	since := time.Now()
	since = since.AddDate(0, 0, -3)
	if lastModified.Before(since) {
		logging.Log.Warnf("OVAL for %s %s is old, last modified is %s. It's recommended to update OVAL to improve scanning accuracy. How to update OVAL database, see https://github.com/vulsio/goval-dictionary#usage",
			ovalFamily, ovalRelease, lastModified)
		return false, nil
	}
	logging.Log.Infof("OVAL %s %s is fresh. lastModified: %s", ovalFamily, ovalRelease, lastModified.Format(time.RFC3339))
	return true, nil
}

// NewOvalDB returns oval db client
func newOvalDB(cnf config.VulnDictInterface) (ovaldb.DB, error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, locked, err := ovaldb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), ovaldb.Option{})
	if err != nil {
		if locked {
			return nil, xerrors.Errorf("Failed to init OVAL DB. SQLite3: %s is locked. err: %w, ", cnf.GetSQLite3Path(), err)
		}
		return nil, xerrors.Errorf("Failed to init OVAL DB. DB Path: %s, err: %w", path, err)
	}
	return driver, nil
}
