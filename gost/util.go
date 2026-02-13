//go:build !scanner

package gost

import (
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
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
	for range nReq {
		tasks <- func() {
			req := <-reqChan
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

	var timeout <-chan time.Time
	if config.Conf.Gost.TimeoutSec > 0 {
		timeout = time.After(time.Duration(config.Conf.Gost.TimeoutSec) * time.Second)
	}
	var errs []error
	for range nReq {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, xerrors.New("Timeout Fetching Gost")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch Gost. err: %w", errs)
	}
	return
}

type request struct {
	packName  string
	isSrcPack bool
	cveID     string
}

func getCvesWithFixStateViaHTTP(r *models.ScanResult, urlPrefix, fixState string) (responses []response, err error) {
	nReq := len(r.SrcPackages)
	reqChan := make(chan request, nReq)
	resChan := make(chan response, nReq)
	errChan := make(chan error, nReq)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, pack := range r.SrcPackages {
			n := pack.Name
			if models.IsKernelSourcePackage(r.Family, pack.Name) {
				n = models.RenameKernelSourcePackageName(r.Family, pack.Name)
			}
			reqChan <- request{
				packName:  n,
				isSrcPack: true,
			}
		}
	}()

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range nReq {
		tasks <- func() {
			req := <-reqChan
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

	var timeout <-chan time.Time
	if config.Conf.Gost.TimeoutSec > 0 {
		timeout = time.After(time.Duration(config.Conf.Gost.TimeoutSec) * time.Second)
	}
	var errs []error
	for range nReq {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, xerrors.New("Timeout Fetching Gost")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch Gost. err: %w", errs)
	}
	return
}

func httpGet(url string, req request, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	count, retryMax := 0, 3
	f := func() (err error) {
		req := gorequest.New().Get(url)
		if config.Conf.Gost.TimeoutSecPerRequest > 0 {
			req = req.Timeout(time.Duration(config.Conf.Gost.TimeoutSecPerRequest) * time.Second)
		}
		resp, body, errs = req.End()
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
		logging.Log.Warnf("Failed to HTTP GET. retrying in %f seconds. err: %+v", t.Seconds(), err)
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

func unique[T comparable](s []T) []T {
	m := map[T]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	return slices.Collect(maps.Keys(m))
}
