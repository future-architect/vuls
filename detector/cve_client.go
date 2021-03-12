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
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	cvelog "github.com/kotakanbe/go-cve-dictionary/log"
	cvemodels "github.com/kotakanbe/go-cve-dictionary/models"
)

type goCveDictClient struct {
	cnf config.GoCveDictConf
}

func newGoCveDictClient(cnf config.GoCveDictConf, o logging.LogOpts) goCveDictClient {
	cvelog.SetLogger(o.LogDir, o.Quiet, o.Debug, false)
	return goCveDictClient{cnf: cnf}
}

type response struct {
	Key       string
	CveDetail cvemodels.CveDetail
}

func (api goCveDictClient) fetchCveDetails(driver cvedb.DB, cveIDs []string) (cveDetails []cvemodels.CveDetail, err error) {
	if driver == nil {
		return
	}
	for _, cveID := range cveIDs {
		cveDetail, err := driver.Get(cveID)
		if err != nil {
			return nil, xerrors.Errorf("Failed to fetch CVE. err: %w", err)
		}
		if len(cveDetail.CveID) == 0 {
			cveDetails = append(cveDetails, cvemodels.CveDetail{CveID: cveID})
		} else {
			cveDetails = append(cveDetails, *cveDetail)
		}
	}
	return
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
				url, err := util.URLPathJoin(api.cnf.URL, "cves", cveID)
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
			if len(res.CveDetail.CveID) == 0 {
				cveDetails = append(cveDetails, cvemodels.CveDetail{
					CveID: res.Key,
				})
			} else {
				cveDetails = append(cveDetails, res.CveDetail)
			}
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
		logging.Log.Warnf("Failed to HTTP GET. retrying in %s seconds. err: %+v",
			t, err)
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

func (api goCveDictClient) fetchCveDetailsByCpeName(driver cvedb.DB, cpeName string) ([]cvemodels.CveDetail, error) {
	if api.cnf.IsFetchViaHTTP() {
		url, err := util.URLPathJoin(api.cnf.URL, "cpes")
		if err != nil {
			return nil, err
		}

		query := map[string]string{"name": cpeName}
		logging.Log.Debugf("HTTP Request to %s, query: %#v", url, query)
		return api.httpPost(cpeName, url, query)
	}
	return driver.GetByCpeURI(cpeName)
}

func (api goCveDictClient) httpPost(key, url string, query map[string]string) ([]cvemodels.CveDetail, error) {
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
