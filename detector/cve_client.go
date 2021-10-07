//go:build !scanner
// +build !scanner

package detector

import (
	"encoding/json"
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
	cnf    config.VulnDictInterface
	driver cvedb.DB
}

func newGoCveDictClient(cnf config.VulnDictInterface, o logging.LogOpts) (*goCveDictClient, error) {
	if err := cvelog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return nil, err
	}

	driver, locked, err := newCveDB(cnf)
	if locked {
		return nil, xerrors.Errorf("SQLite3 is locked: %s", cnf.GetSQLite3Path())
	} else if err != nil {
		return nil, err
	}
	return &goCveDictClient{cnf: cnf, driver: driver}, nil
}

func (api goCveDictClient) closeDB() error {
	if api.driver == nil {
		return nil
	}
	return api.driver.CloseDB()
}

func (api goCveDictClient) fetchCveDetails(cveIDs []string) (cveDetails []cvemodels.CveDetail, err error) {
	m, err := api.driver.GetMulti(cveIDs)
	if err != nil {
		return nil, xerrors.Errorf("Failed to GetMulti. err: %w", err)
	}
	for _, v := range m {
		cveDetails = append(cveDetails, v)
	}
	return cveDetails, nil
}

type response struct {
	Key       string
	CveDetail cvemodels.CveDetail
}

func (api goCveDictClient) fetchCveDetailsViaHTTP(cveIDs []string) (cveDetails []cvemodels.CveDetail, err error) {
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

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range cveIDs {
		tasks <- func() {
			select {
			case cveID := <-reqChan:
				url, err := util.URLPathJoin(api.cnf.GetURL(), "cves", cveID)
				if err != nil {
					errChan <- err
				} else {
					logging.Log.Debugf("HTTP Request to %s", url)
					api.httpGet(cveID, url, resChan, errChan)
				}
			}
		}
	}

	timeout := time.After(2 * 60 * time.Second)
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
	return
}

func (api goCveDictClient) httpGet(key, url string, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		resp, body, errs = gorequest.New().Timeout(10 * time.Second).Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return xerrors.Errorf("HTTP GET Error, url: %s, resp: %v, err: %+v",
				url, resp, errs)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		logging.Log.Warnf("Failed to HTTP GET. retrying in %s seconds. err: %+v", t, err)
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

func (api goCveDictClient) detectCveByCpeURI(cpeURI string, useJVN bool) (cves []cvemodels.CveDetail, err error) {
	if api.cnf.IsFetchViaHTTP() {
		url, err := util.URLPathJoin(api.cnf.GetURL(), "cpes")
		if err != nil {
			return nil, err
		}

		query := map[string]string{"name": cpeURI}
		logging.Log.Debugf("HTTP Request to %s, query: %#v", url, query)
		if cves, err = api.httpPost(url, query); err != nil {
			return nil, err
		}
	} else {
		if cves, err = api.driver.GetByCpeURI(cpeURI); err != nil {
			return nil, err
		}
	}

	if useJVN {
		return cves, nil
	}

	nvdCves := []cvemodels.CveDetail{}
	for _, cve := range cves {
		if !cve.HasNvd() {
			continue
		}
		cve.Jvns = []cvemodels.Jvn{}
		nvdCves = append(nvdCves, cve)
	}
	return nvdCves, nil
}

func (api goCveDictClient) httpPost(url string, query map[string]string) ([]cvemodels.CveDetail, error) {
	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		req := gorequest.New().Timeout(10 * time.Second).Post(url)
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
		logging.Log.Warnf("Failed to HTTP POST. retrying in %s seconds. err: %+v", t, err)
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

func newCveDB(cnf config.VulnDictInterface) (driver cvedb.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, locked, err = cvedb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL())
	if err != nil {
		err = xerrors.Errorf("Failed to init CVE DB. err: %w, path: %s", err, path)
		return nil, locked, err
	}
	return driver, false, nil
}
