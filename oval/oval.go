package oval

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ver "github.com/knqyf263/go-deb-version"
	"github.com/kotakanbe/goval-dictionary/db"
	ovallog "github.com/kotakanbe/goval-dictionary/log"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
	"github.com/parnurzeal/gorequest"
)

// Client is the interface of OVAL client.
type Client interface {
	CheckHTTPHealth() error
	FillWithOval(r *models.ScanResult) error

	// CheckIfOvalFetched checks if oval entries are in DB by family, release.
	CheckIfOvalFetched(string, string) (bool, error)
	CheckIfOvalFresh(string, string) (bool, error)
}

// Base is a base struct
type Base struct{}

// CheckHTTPHealth do health check
func (b Base) CheckHTTPHealth() error {
	if !b.isFetchViaHTTP() {
		return nil
	}

	url := fmt.Sprintf("%s/health", config.Conf.OvalDBURL)
	var errs []error
	var resp *http.Response
	resp, _, errs = gorequest.New().Get(url).End()
	//  resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return fmt.Errorf("Failed to request to OVAL server. url: %s, errs: %v",
			url, errs)
	}
	return nil
}

// CheckIfOvalFetched checks if oval entries are in DB by family, release.
func (b Base) CheckIfOvalFetched(osFamily, release string) (fetched bool, err error) {
	ovallog.Initialize(config.Conf.LogDir)
	if !b.isFetchViaHTTP() {
		var ovaldb db.DB
		if ovaldb, err = db.NewDB(
			osFamily,
			config.Conf.OvalDBType,
			config.Conf.OvalDBPath,
			config.Conf.DebugSQL,
		); err != nil {
			return false, err
		}
		defer ovaldb.CloseDB()
		count, err := ovaldb.CountDefs(osFamily, release)
		if err != nil {
			return false, fmt.Errorf("Failed to count OVAL defs: %s, %s, %v",
				osFamily, release, err)
		}
		return 0 < count, nil
	}

	url, _ := util.URLPathJoin(config.Conf.OvalDBURL, "count", osFamily, release)
	resp, body, errs := gorequest.New().Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return false, fmt.Errorf("HTTP GET error: %v, url: %s, resp: %v",
			errs, url, resp)
	}
	count := 0
	if err := json.Unmarshal([]byte(body), &count); err != nil {
		return false, fmt.Errorf("Failed to Unmarshall. body: %s, err: %s",
			body, err)
	}
	return 0 < count, nil
}

// CheckIfOvalFresh checks if oval entries are fresh enough
func (b Base) CheckIfOvalFresh(osFamily, release string) (ok bool, err error) {
	ovallog.Initialize(config.Conf.LogDir)
	var lastModified time.Time
	if !b.isFetchViaHTTP() {
		var ovaldb db.DB
		if ovaldb, err = db.NewDB(
			osFamily,
			config.Conf.OvalDBType,
			config.Conf.OvalDBPath,
			config.Conf.DebugSQL,
		); err != nil {
			return false, err
		}
		defer ovaldb.CloseDB()
		lastModified = ovaldb.GetLastModified(osFamily, release)
	} else {
		url, _ := util.URLPathJoin(config.Conf.OvalDBURL, "lastmodified", osFamily, release)
		resp, body, errs := gorequest.New().Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return false, fmt.Errorf("HTTP GET error: %v, url: %s, resp: %v",
				errs, url, resp)
		}

		if err := json.Unmarshal([]byte(body), &lastModified); err != nil {
			return false, fmt.Errorf("Failed to Unmarshall. body: %s, err: %s",
				body, err)
		}
	}

	major := strings.Split(release, ".")[0]
	since := time.Now()
	since = since.AddDate(0, 0, -3)
	if lastModified.Before(since) {
		util.Log.Warnf("OVAL for %s %s is old, last modified is %s. It's recommended to update OVAL to improve scanning accuracy. How to update OVAL database, see https://github.com/kotakanbe/goval-dictionary#usage",
			osFamily, major, lastModified)
		return false, nil
	}
	util.Log.Infof("OVAL is fresh: %s %s ", osFamily, major)
	return true, nil
}

func (b Base) isFetchViaHTTP() bool {
	// Default value of OvalDBType is sqlite3
	if config.Conf.OvalDBURL != "" && config.Conf.OvalDBType == "sqlite3" {
		return true
	}
	return false
}

type request struct {
	pack models.Package
}

type response struct {
	pack *models.Package
	defs []ovalmodels.Definition
}

// getDefsByPackNameViaHTTP fetches OVAL information via HTTP
func getDefsByPackNameViaHTTP(r *models.ScanResult) (
	relatedDefs []ovalmodels.Definition, err error) {

	reqChan := make(chan request, len(r.Packages))
	resChan := make(chan response, len(r.Packages))
	errChan := make(chan error, len(r.Packages))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, pack := range r.Packages {
			reqChan <- request{
				pack: pack,
			}
		}
	}()

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range r.Packages {
		tasks <- func() {
			select {
			case req := <-reqChan:
				url, err := util.URLPathJoin(
					config.Conf.OvalDBURL,
					"packs",
					r.Family,
					r.Release,
					req.pack.Name,
				)
				if err != nil {
					errChan <- err
				} else {
					util.Log.Debugf("HTTP Request to %s", url)
					httpGet(url, &req.pack, resChan, errChan)
				}
			}
		}
	}

	timeout := time.After(2 * 60 * time.Second)
	var errs []error
	for range r.Packages {
		select {
		case res := <-resChan:
			current, _ := ver.NewVersion(fmt.Sprintf("%s-%s",
				res.pack.Version, res.pack.Release))
			for _, def := range res.defs {
				for _, p := range def.AffectedPacks {
					affected, _ := ver.NewVersion(p.Version)
					if res.pack.Name != p.Name || !current.LessThan(affected) {
						continue
					}
					relatedDefs = append(relatedDefs, def)
				}
			}
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, fmt.Errorf("Timeout Fetching OVAL")
		}
	}
	if len(errs) != 0 {
		return nil, fmt.Errorf("Failed to fetch OVAL. err: %v", errs)
	}
	return
}

func httpGet(url string, pack *models.Package, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	count, retryMax := 0, 3
	f := func() (err error) {
		//  resp, body, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
		resp, body, errs = gorequest.New().Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			count++
			if count == retryMax {
				return nil
			}
			return fmt.Errorf("HTTP GET error: %v, url: %s, resp: %v",
				errs, url, resp)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		util.Log.Warnf("Failed to HTTP GET. retrying in %s seconds. err: %s", t, err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		errChan <- fmt.Errorf("HTTP Error %s", err)
		return
	}
	if count == retryMax {
		errChan <- fmt.Errorf("HRetry count exceeded")
		return
	}

	defs := []ovalmodels.Definition{}
	if err := json.Unmarshal([]byte(body), &defs); err != nil {
		errChan <- fmt.Errorf("Failed to Unmarshall. body: %s, err: %s",
			body, err)
		return
	}
	resChan <- response{
		pack: pack,
		defs: defs,
	}
}

func getPackages(r *models.ScanResult, d *ovalmodels.Definition) (names []string) {
	for _, affectedPack := range d.AffectedPacks {
		names = append(names, affectedPack.Name)
	}
	return
}
