//go:build !scanner

package detector

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/util"
	cvedb "github.com/vulsio/go-cve-dictionary/db"
	cvelog "github.com/vulsio/go-cve-dictionary/log"
	cvemodels "github.com/vulsio/go-cve-dictionary/models"
)

type goCveDictClient struct {
	driver  cvedb.DB
	baseURL string
}

func newGoCveDictClient(cnf config.VulnDictInterface, o logging.LogOpts) (*goCveDictClient, error) {
	if err := cvelog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return nil, xerrors.Errorf("Failed to set go-cve-dictionary logger. err: %w", err)
	}

	driver, err := newCveDB(cnf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to newCveDB. err: %w", err)
	}
	return &goCveDictClient{driver: driver, baseURL: cnf.GetURL()}, nil
}

func (client goCveDictClient) closeDB() error {
	if client.driver == nil {
		return nil
	}
	return client.driver.CloseDB()
}

type response struct {
	Key       string
	CveDetail cvemodels.CveDetail
}

func (client goCveDictClient) fetchCveDetails(cveIDs []string) (cveDetails []cvemodels.CveDetail, err error) {
	if client.driver == nil {
		reqChan := make(chan string, len(cveIDs))
		resChan := make(chan response, len(cveIDs))
		errChan := make(chan error, len(cveIDs))
		defer close(reqChan)
		defer close(resChan)
		defer close(errChan)

		go func() {
			for _, cveID := range cveIDs {
				reqChan <- cveID
			}
		}()

		// Increase concurrency for better performance: 50 workers for normal loads, 100 for heavy loads
		concurrency := 50
		if len(cveIDs) > 500 {
			concurrency = 100
		}
		tasks := util.GenWorkers(concurrency)
		for range cveIDs {
			tasks <- func() {
				cveID := <-reqChan
				url, err := util.URLPathJoin(client.baseURL, "cves", cveID)
				if err != nil {
					errChan <- err
				} else {
					logging.Log.Debugf("HTTP Request to %s", url)
					httpGet(cveID, url, resChan, errChan)
				}
			}
		}

		var timeout <-chan time.Time
		if config.Conf.CveDict.TimeoutSec > 0 {
			timeout = time.After(time.Duration(config.Conf.CveDict.TimeoutSec) * time.Second)
		}
		var errs []error
		for range cveIDs {
			select {
			case res := <-resChan:
				cveDetails = append(cveDetails, res.CveDetail)
			case err := <-errChan:
				errs = append(errs, err)
			case <-timeout:
				return nil, xerrors.New("Timeout Fetching CVE")
			}
		}
		if len(errs) != 0 {
			return nil,
				xerrors.Errorf("Failed to fetch CVE. err: %w", errs)
		}
	} else {
		m, err := client.driver.GetMulti(cveIDs)
		if err != nil {
			return nil, xerrors.Errorf("Failed to GetMulti. err: %w", err)
		}
		for _, v := range m {
			cveDetails = append(cveDetails, v)
		}
	}
	return cveDetails, nil
}

func httpGet(key, url string, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		req := gorequest.New().Get(url)
		if config.Conf.CveDict.TimeoutSecPerRequest > 0 {
			req = req.Timeout(time.Duration(config.Conf.CveDict.TimeoutSecPerRequest) * time.Second)
		}
		resp, body, errs = req.End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return xerrors.Errorf("HTTP GET Error, url: %s, resp: %v, err: %+v",
				url, resp, errs)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		logging.Log.Warnf("Failed to HTTP GET. retrying in %f seconds. err: %+v", t.Seconds(), err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		errChan <- xerrors.Errorf("HTTP Error: %w", err)
		return
	}
	cveDetail := cvemodels.CveDetail{}
	if err := json.Unmarshal([]byte(body), &cveDetail); err != nil {
		errChan <- xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		return
	}
	resChan <- response{
		key,
		cveDetail,
	}
}

func (client goCveDictClient) detectCveByCpeURI(cpeURI string, useJVN bool) (cves []cvemodels.CveDetail, err error) {
	if client.driver == nil {
		url, err := util.URLPathJoin(client.baseURL, "cpes")
		if err != nil {
			return nil, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}

		query := map[string]string{"name": cpeURI}
		logging.Log.Debugf("HTTP Request to %s, query: %#v", url, query)
		if cves, err = httpPost(url, query); err != nil {
			return nil, xerrors.Errorf("Failed to post HTTP Request. err: %w", err)
		}
	} else {
		if cves, err = client.driver.GetByCpeURI(cpeURI); err != nil {
			return nil, xerrors.Errorf("Failed to get CVEs by CPEURI. err: %w", err)
		}
	}

	if useJVN {
		return cves, nil
	}

	filtered := []cvemodels.CveDetail{}
	for _, cve := range cves {
		if !cve.HasNvd() && !cve.HasFortinet() && !cve.HasPaloalto() && !cve.HasCisco() {
			continue
		}
		cve.Jvns = []cvemodels.Jvn{}
		filtered = append(filtered, cve)
	}
	return filtered, nil
}

func httpPost(url string, query map[string]string) ([]cvemodels.CveDetail, error) {
	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		req := gorequest.New().Post(url)
		if config.Conf.CveDict.TimeoutSecPerRequest > 0 {
			req = req.Timeout(time.Duration(config.Conf.CveDict.TimeoutSecPerRequest) * time.Second)
		}
		for key := range query {
			req = req.Send(fmt.Sprintf("%s=%s", key, query[key])).Type("json")
		}
		resp, body, errs = req.End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return xerrors.Errorf("HTTP POST error. url: %s, resp: %v, err: %+v", url, resp, errs)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		logging.Log.Warnf("Failed to HTTP POST. retrying in %f seconds. err: %+v", t.Seconds(), err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		return nil, xerrors.Errorf("HTTP Error: %w", err)
	}

	cveDetails := []cvemodels.CveDetail{}
	if err := json.Unmarshal([]byte(body), &cveDetails); err != nil {
		return nil,
			xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
	}
	return cveDetails, nil
}

func newCveDB(cnf config.VulnDictInterface) (cvedb.DB, error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, err := cvedb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), cvedb.Option{})
	if err != nil {
		if errors.Is(err, cvedb.ErrDBLocked) {
			return nil, xerrors.Errorf("Failed to init CVE DB. SQLite3: %s is locked. err: %w", cnf.GetSQLite3Path(), err)
		}
		return nil, xerrors.Errorf("Failed to init CVE DB. DB Path: %s, err: %w", path, err)
	}
	return driver, nil
}
