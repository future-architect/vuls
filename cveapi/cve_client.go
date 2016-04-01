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
	api.initialize()
	url := fmt.Sprintf("%s/health", api.baseURL)
	var errs []error
	var resp *http.Response
	resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if len(errs) > 0 || resp.StatusCode != 200 {
		return false, fmt.Errorf("Failed to request to CVE server. url: %s, errs: %v",
			url,
			errs,
		)
	}
	return true, nil
}

type response struct {
	Key       string
	CveDetail cve.CveDetail
}

func (api cvedictClient) FetchCveDetails(cveIDs []string) (cveDetails cve.CveDetails, err error) {
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

	// order by CVE ID desc
	sort.Sort(cveDetails)
	return
}

func (api cvedictClient) httpGet(key, url string, resChan chan<- response, errChan chan<- error) {

	var body string
	var errs []error
	var resp *http.Response
	f := func() (err error) {
		resp, body, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
		if len(errs) > 0 || resp.StatusCode != 200 {
			errChan <- fmt.Errorf("HTTP error. errs: %v, url: %s", errs, url)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log.Warnf("Failed to get. retrying in %s seconds. err: %s", t, err)
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

//  func (api cvedictClient) httpGet(key, url string, query map[string]string, resChan chan<- response, errChan chan<- error) {

//      var body string
//      var errs []error
//      var resp *http.Response
//      f := func() (err error) {
//          req := gorequest.New().SetDebug(true).Proxy(api.httpProxy).Get(url)
//          for key := range query {
//              req = req.Query(fmt.Sprintf("%s=%s", key, query[key])).Set("Content-Type", "application/x-www-form-urlencoded")
//          }
//          pp.Println(req)
//          resp, body, errs = req.End()
//          if len(errs) > 0 || resp.StatusCode != 200 {
//              errChan <- fmt.Errorf("HTTP error. errs: %v, url: %s", errs, url)
//          }
//          return nil
//      }
//      notify := func(err error, t time.Duration) {
//          log.Warnf("Failed to get. retrying in %s seconds. err: %s", t, err)
//      }
//      err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
//      if err != nil {
//          errChan <- fmt.Errorf("HTTP Error %s", err)
//      }
//      //  resChan <- body
//      cveDetail := cve.CveDetail{}
//      if err := json.Unmarshal([]byte(body), &cveDetail); err != nil {
//          errChan <- fmt.Errorf("Failed to Unmarshall. body: %s, err: %s", body, err)
//      }
//      resChan <- response{
//          key,
//          cveDetail,
//      }
//  }

type responseGetCveDetailByCpeName struct {
	CpeName    string
	CveDetails []cve.CveDetail
}

func (api cvedictClient) FetchCveDetailsByCpeName(cpeName string) ([]cve.CveDetail, error) {
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
		if len(errs) > 0 || resp.StatusCode != 200 {
			return fmt.Errorf("HTTP error. errs: %v, url: %s", errs, url)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		log.Warnf("Failed to get. retrying in %s seconds. err: %s", t, err)
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
