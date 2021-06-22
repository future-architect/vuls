// +build !scanner

package gost

import (
	"net/http"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

type response struct {
	request request
	json    string
}

func getCvesViaHTTP(cveIDs []string, urlPrefix string) (
	responses []response, err error) {
	nReq := len(cveIDs)
	reqChan := make(chan request, nReq)
	resChan := make(chan response, nReq)
	errChan := make(chan error, nReq)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, cveID := range cveIDs {
			reqChan <- request{
				cveID: cveID,
			}
		}
	}()

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for i := 0; i < nReq; i++ {
		tasks <- func() {
			select {
			case req := <-reqChan:
				url, err := util.URLPathJoin(
					urlPrefix,
					req.cveID,
				)
				if err != nil {
					errChan <- err
				} else {
					logging.Log.Debugf("HTTP Request to %s", url)
					httpGet(url, req, resChan, errChan)
				}
			}
		}
	}

	timeout := time.After(2 * 60 * time.Second)
	var errs []error
	for i := 0; i < nReq; i++ {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, xerrors.New("Timeout Fetching OVAL")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch OVAL. err: %w", errs)
	}
	return
}

type request struct {
	osMajorVersion string
	packName       string
	isSrcPack      bool
	cveID          string
}

func getAllUnfixedCvesViaHTTP(r *models.ScanResult, urlPrefix string) (
	responses []response, err error) {
	return getCvesWithFixStateViaHTTP(r, urlPrefix, "unfixed-cves")
}

func getCvesWithFixStateViaHTTP(r *models.ScanResult, urlPrefix, fixState string) (responses []response, err error) {
	nReq := len(r.Packages) + len(r.SrcPackages)
	reqChan := make(chan request, nReq)
	resChan := make(chan response, nReq)
	errChan := make(chan error, nReq)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, pack := range r.Packages {
			reqChan <- request{
				osMajorVersion: major(r.Release),
				packName:       pack.Name,
				isSrcPack:      false,
			}
		}
		for _, pack := range r.SrcPackages {
			reqChan <- request{
				osMajorVersion: major(r.Release),
				packName:       pack.Name,
				isSrcPack:      true,
			}
		}
	}()

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for i := 0; i < nReq; i++ {
		tasks <- func() {
			select {
			case req := <-reqChan:
				url, err := util.URLPathJoin(
					urlPrefix,
					req.packName,
					fixState,
				)
				if err != nil {
					errChan <- err
				} else {
					logging.Log.Debugf("HTTP Request to %s", url)
					httpGet(url, req, resChan, errChan)
				}
			}
		}
	}

	timeout := time.After(2 * 60 * time.Second)
	var errs []error
	for i := 0; i < nReq; i++ {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, xerrors.New("Timeout Fetching OVAL")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch OVAL. err: %w", errs)
	}
	return
}

func httpGet(url string, req request, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	count, retryMax := 0, 3
	f := func() (err error) {
		//  resp, body, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
		resp, body, errs = gorequest.New().Timeout(10 * time.Second).Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			count++
			if count == retryMax {
				return nil
			}
			return xerrors.Errorf("HTTP GET error, url: %s, resp: %v, err: %+v", url, resp, errs)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		logging.Log.Warnf("Failed to HTTP GET. retrying in %s seconds. err: %+v", t, err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		errChan <- xerrors.Errorf("HTTP Error %w", err)
		return
	}
	if count == retryMax {
		errChan <- xerrors.New("Retry count exceeded")
		return
	}

	resChan <- response{
		request: req,
		json:    body,
	}
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
