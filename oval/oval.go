// +build !scanner

package oval

import (
	"encoding/json"
	"time"

	cnf "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/kotakanbe/goval-dictionary/db"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

// Client is the interface of OVAL client.
type Client interface {
	FillWithOval(db.DB, *models.ScanResult) (int, error)

	// CheckIfOvalFetched checks if oval entries are in DB by family, release.
	CheckIfOvalFetched(db.DB, string, string) (bool, error)
	CheckIfOvalFresh(db.DB, string, string) (bool, error)
}

// Base is a base struct
type Base struct {
	family string
}

// CheckIfOvalFetched checks if oval entries are in DB by family, release.
func (b Base) CheckIfOvalFetched(driver db.DB, osFamily, release string) (fetched bool, err error) {
	if !cnf.Conf.OvalDict.IsFetchViaHTTP() {
		count, err := driver.CountDefs(osFamily, release)
		if err != nil {
			return false, xerrors.Errorf("Failed to count OVAL defs: %s, %s, %w", osFamily, release, err)
		}
		return 0 < count, nil
	}

	url, _ := util.URLPathJoin(cnf.Conf.OvalDict.URL, "count", osFamily, release)
	resp, body, errs := gorequest.New().Timeout(10 * time.Second).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return false, xerrors.Errorf("HTTP GET error, url: %s, resp: %v, err: %+v", url, resp, errs)
	}
	count := 0
	if err := json.Unmarshal([]byte(body), &count); err != nil {
		return false, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
	}
	return 0 < count, nil
}

// CheckIfOvalFresh checks if oval entries are fresh enough
func (b Base) CheckIfOvalFresh(driver db.DB, osFamily, release string) (ok bool, err error) {
	var lastModified time.Time
	if !cnf.Conf.OvalDict.IsFetchViaHTTP() {
		lastModified = driver.GetLastModified(osFamily, release)
	} else {
		url, _ := util.URLPathJoin(cnf.Conf.OvalDict.URL, "lastmodified", osFamily, release)
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
	logging.Log.Infof("OVAL is fresh: %s %s ", osFamily, release)
	return true, nil
}
