/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package cveapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/parnurzeal/gorequest"

	log "github.com/Sirupsen/logrus"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/util"
	cveconfig "github.com/kotakanbe/go-cve-dictionary/config"
	cvedb "github.com/kotakanbe/go-cve-dictionary/db"
	cve "github.com/kotakanbe/go-cve-dictionary/models"
)

// CveClient is api client of CVE disctionary service.
var CveClient cvedictClient

type cvedictClient struct {
	//  httpProxy string
	baseURL string
}

func (api *cvedictClient) initialize() {
	api.baseURL = config.Conf.CveDictionaryURL
}

func (api cvedictClient) CheckHealth() (ok bool, err error) {
	if config.Conf.CveDictionaryURL == "" {
		log.Debugf("get cve-dictionary from %s", config.Conf.CveDBType)
		return true, nil
	}

	api.initialize()
	url := fmt.Sprintf("%s/health", api.baseURL)
	var errs []error
	var resp *http.Response
	resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return false, fmt.Errorf("Failed to request to CVE server. url: %s, errs: %v", url, errs)
	}
	return true, nil
}

type response struct {
	Key       string
	CveDetail cve.CveDetail
}

func (api cvedictClient) FetchCveDetails(cveIDs []string) (cveDetails cve.CveDetails, err error) {
	if config.Conf.CveDictionaryURL == "" {
		return api.FetchCveDetailsFromCveDB(cveIDs)
	}

	api.baseURL = config.Conf.CveDictionaryURL
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
				url, err := util.URLPathJoin(api.baseURL, "cves", cveID)
				if err != nil {
					errChan <- err
				} else {
					log.Debugf("HTTP Request to %s", url)
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
				cveDetails = append(cveDetails, cve.CveDetail{
					CveID: res.Key,
				})
			} else {
				cveDetails = append(cveDetails, res.CveDetail)
			}
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return []cve.CveDetail{}, fmt.Errorf("Timeout Fetching CVE")
		}
	}
	if len(errs) != 0 {
		return []cve.CveDetail{},
			fmt.Errorf("Failed to fetch CVE. err: %v", errs)
	}

	sort.Sort(cveDetails)
	return
}

func (api cvedictClient) FetchCveDetailsFromCveDB(cveIDs []string) (cveDetails cve.CveDetails, err error) {
	log.Debugf("open cve-dictionary db (%s)", config.Conf.CveDBType)
	cveconfig.Conf.DBType = config.Conf.CveDBType
	if config.Conf.CveDBType == "sqlite3" {
		cveconfig.Conf.DBPath = config.Conf.CveDBPath
	} else {
		cveconfig.Conf.DBPath = config.Conf.CveDictionaryURL
	}
	cveconfig.Conf.DebugSQL = config.Conf.DebugSQL
	if err := cvedb.OpenDB(); err != nil {
		return []cve.CveDetail{},
			fmt.Errorf("Failed to open DB. err: %s", err)
	}
	for _, cveID := range cveIDs {
		cveDetail := cvedb.Get(cveID)
		if len(cveDetail.CveID) == 0 {
			cveDetails = append(cveDetails, cve.CveDetail{
				CveID: cveID,
			})
		} else {
			cveDetails = append(cveDetails, cveDetail)
		}
	}

	// order by CVE ID desc
	sort.Sort(cveDetails)
	return
}

func (api cvedictClient) httpGet(key, url string, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		//  resp, body, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
		resp, body, errs = gorequest.New().Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return fmt.Errorf("HTTP GET error: %v, url: %s, resp: %v", errs, url, resp)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log.Warnf("Failed to HTTP GET. retrying in %s seconds. err: %s", t, err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		errChan <- fmt.Errorf("HTTP Error %s", err)
	}
	cveDetail := cve.CveDetail{}
	if err := json.Unmarshal([]byte(body), &cveDetail); err != nil {
		errChan <- fmt.Errorf("Failed to Unmarshall. body: %s, err: %s", body, err)
	}
	resChan <- response{
		key,
		cveDetail,
	}
}

type responseGetCveDetailByCpeName struct {
	CpeName    string
	CveDetails []cve.CveDetail
}

func (api cvedictClient) FetchCveDetailsByCpeName(cpeName string) ([]cve.CveDetail, error) {
	if config.Conf.CveDictionaryURL == "" {
		return api.FetchCveDetailsByCpeNameFromDB(cpeName)
	}

	api.baseURL = config.Conf.CveDictionaryURL
	url, err := util.URLPathJoin(api.baseURL, "cpes")
	if err != nil {
		return []cve.CveDetail{}, err
	}

	query := map[string]string{"name": cpeName}
	log.Debugf("HTTP Request to %s, query: %#v", url, query)
	return api.httpPost(cpeName, url, query)
}

func (api cvedictClient) httpPost(key, url string, query map[string]string) ([]cve.CveDetail, error) {
	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		req := gorequest.New().SetDebug(config.Conf.Debug).Post(url)
		for key := range query {
			req = req.Send(fmt.Sprintf("%s=%s", key, query[key])).Type("json")
		}
		resp, body, errs = req.End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			return fmt.Errorf("HTTP POST error: %v, url: %s, resp: %v", errs, url, resp)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log.Warnf("Failed to HTTP POST. retrying in %s seconds. err: %s", t, err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		return []cve.CveDetail{}, fmt.Errorf("HTTP Error %s", err)
	}

	cveDetails := []cve.CveDetail{}
	if err := json.Unmarshal([]byte(body), &cveDetails); err != nil {
		return []cve.CveDetail{},
			fmt.Errorf("Failed to Unmarshall. body: %s, err: %s", body, err)
	}
	return cveDetails, nil
}

func (api cvedictClient) FetchCveDetailsByCpeNameFromDB(cpeName string) ([]cve.CveDetail, error) {
	log.Debugf("open cve-dictionary db (%s)", config.Conf.CveDBType)
	cveconfig.Conf.DBType = config.Conf.CveDBType
	cveconfig.Conf.DBPath = config.Conf.CveDBPath
	cveconfig.Conf.DebugSQL = config.Conf.DebugSQL

	if err := cvedb.OpenDB(); err != nil {
		return []cve.CveDetail{},
			fmt.Errorf("Failed to open DB. err: %s", err)
	}
	return cvedb.GetByCpeName(cpeName), nil
}
