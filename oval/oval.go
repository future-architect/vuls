// +build !scanner

package oval

import (
	"encoding/json"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

// Client is the interface of OVAL client.
type Client interface {
	FillWithOval(*models.ScanResult) (int, error)
	CheckIfOvalFetched(string, string) (bool, error)
	CheckIfOvalFresh(string, string) (bool, error)
}

// Base is a base struct
type Base struct {
	family string
	Cnf    config.VulnDictInterface
}

// CheckIfOvalFetched checks if oval entries are in DB by family, release.
func (b Base) CheckIfOvalFetched(osFamily, release string) (fetched bool, err error) {
	ovalFamily, err := GetFamilyInOval(osFamily)
	if err != nil {
		return false, err
	}
	if !b.Cnf.IsFetchViaHTTP() {
		driver, err := newOvalDB(b.Cnf, ovalFamily)
		if err != nil {
			return false, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

		count, err := driver.CountDefs(ovalFamily, release)
		if err != nil {
			return false, xerrors.Errorf("Failed to count OVAL defs: %s, %s, %w", ovalFamily, release, err)
		}
		logging.Log.Infof("OVAL %s %s found. defs: %d", osFamily, release, count)
		return 0 < count, nil
	}

	url, _ := util.URLPathJoin(config.Conf.OvalDict.URL, "count", ovalFamily, release)
	resp, body, errs := gorequest.New().Timeout(10 * time.Second).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return false, xerrors.Errorf("HTTP GET error, url: %s, resp: %v, err: %+v", url, resp, errs)
	}
	count := 0
	if err := json.Unmarshal([]byte(body), &count); err != nil {
		return false, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
	}
	logging.Log.Infof("OVAL %s %s is fresh. defs: %d", osFamily, release, count)
	return 0 < count, nil
}

// CheckIfOvalFresh checks if oval entries are fresh enough
func (b Base) CheckIfOvalFresh(osFamily, release string) (ok bool, err error) {
	ovalFamily, err := GetFamilyInOval(osFamily)
	if err != nil {
		return false, err
	}
	var lastModified time.Time
	if !b.Cnf.IsFetchViaHTTP() {
		driver, err := newOvalDB(b.Cnf, ovalFamily)
		if err != nil {
			return false, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()
		lastModified, err = driver.GetLastModified(ovalFamily, release)
		if err != nil {
			return false, xerrors.Errorf("Failed to GetLastModified: %w", err)
		}
	} else {
		url, _ := util.URLPathJoin(config.Conf.OvalDict.URL, "lastmodified", ovalFamily, release)
		resp, body, errs := gorequest.New().Timeout(10 * time.Second).Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return false, xerrors.Errorf("HTTP GET error, url: %s, resp: %v, err: %+v", url, resp, errs)
		}

		if err := json.Unmarshal([]byte(body), &lastModified); err != nil {
			return false, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
	}

	since := time.Now()
	since = since.AddDate(0, 0, -3)
	if lastModified.Before(since) {
		logging.Log.Warnf("OVAL for %s %s is old, last modified is %s. It's recommended to update OVAL to improve scanning accuracy. How to update OVAL database, see https://github.com/kotakanbe/goval-dictionary#usage",
			osFamily, release, lastModified)
		return false, nil
	}
	logging.Log.Infof("OVAL %s %s is fresh. lastModified: %s", osFamily, release, lastModified.Format(time.RFC3339))
	return true, nil
}

// NewOvalDB returns oval db client
func newOvalDB(cnf config.VulnDictInterface, familyInScanResult string) (driver db.DB, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}

	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}

	ovalFamily, err := GetFamilyInOval(familyInScanResult)
	if err != nil {
		return nil, err
	}

	driver, locked, err := db.NewDB(ovalFamily, cnf.GetType(), path, cnf.GetDebugSQL())
	if err != nil {
		if locked {
			err = xerrors.Errorf("SQLite3: %s is locked. err: %w", cnf.GetSQLite3Path(), err)
		}
		err = xerrors.Errorf("Failed to new OVAL DB. err: %w", err)
		return nil, err
	}
	return driver, nil
}
