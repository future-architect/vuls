//go:build !scanner
// +build !scanner

package detector

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	ctidb "github.com/vulsio/go-cti/db"
	ctilog "github.com/vulsio/go-cti/utils"
)

// goCTIDBClient is a DB Driver
type goCTIDBClient struct {
	driver  ctidb.DB
	baseURL string
}

// closeDB close a DB connection
func (client goCTIDBClient) closeDB() error {
	if client.driver == nil {
		return nil
	}
	return client.driver.CloseDB()
}

func newGoCTIDBClient(cnf config.VulnDictInterface, o logging.LogOpts) (*goCTIDBClient, error) {
	if err := ctilog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return nil, xerrors.Errorf("Failed to set go-cti logger. err: %w", err)
	}

	db, err := newCTIDB(cnf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to newCTIDB. err: %w", err)
	}
	return &goCTIDBClient{driver: db, baseURL: cnf.GetURL()}, nil
}

// FillWithCTI :
func FillWithCTI(r *models.ScanResult, cnf config.CtiConf, logOpts logging.LogOpts) error {
	client, err := newGoCTIDBClient(&cnf, logOpts)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	nCti := 0
	if client.driver == nil {
		var cveIDs []string
		for cveID := range r.ScannedCves {
			cveIDs = append(cveIDs, cveID)
		}
		prefix, err := util.URLPathJoin(client.baseURL, "cves")
		if err != nil {
			return err
		}
		responses, err := getCTIsViaHTTP(cveIDs, prefix)
		if err != nil {
			return err
		}
		for _, res := range responses {
			var techniqueIDs []string
			if err := json.Unmarshal([]byte(res.json), &techniqueIDs); err != nil {
				return err
			}
			v, ok := r.ScannedCves[res.request.cveID]
			if ok {
				v.Ctis = techniqueIDs
				nCti++
			}
			r.ScannedCves[res.request.cveID] = v
		}
	} else {
		for cveID, vuln := range r.ScannedCves {
			if cveID == "" {
				continue
			}
			techniqueIDs, err := client.driver.GetTechniqueIDsByCveID(cveID)
			if err != nil {
				return xerrors.Errorf("Failed to get CTIs by CVE-ID. err: %w", err)
			}
			if len(techniqueIDs) == 0 {
				continue
			}
			vuln.Ctis = techniqueIDs
			nCti++
			r.ScannedCves[cveID] = vuln
		}
	}

	logging.Log.Infof("%s: Cyber Threat Intelligences are detected for %d CVEs", r.FormatServerName(), nCti)
	return nil
}

type ctiResponse struct {
	request ctiRequest
	json    string
}

func getCTIsViaHTTP(cveIDs []string, urlPrefix string) (responses []ctiResponse, err error) {
	nReq := len(cveIDs)
	reqChan := make(chan ctiRequest, nReq)
	resChan := make(chan ctiResponse, nReq)
	errChan := make(chan error, nReq)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, cveID := range cveIDs {
			reqChan <- ctiRequest{
				cveID: cveID,
			}
		}
	}()

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for i := 0; i < nReq; i++ {
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
				httpGetCTI(url, req, resChan, errChan)
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
			return nil, xerrors.New("Timeout Fetching CTI")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch CTI. err: %w", errs)
	}
	return
}

type ctiRequest struct {
	cveID string
}

func httpGetCTI(url string, req ctiRequest, resChan chan<- ctiResponse, errChan chan<- error) {
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
	if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
		errChan <- xerrors.Errorf("HTTP Error %w", err)
		return
	}
	if count == retryMax {
		errChan <- xerrors.New("Retry count exceeded")
		return
	}

	resChan <- ctiResponse{
		request: req,
		json:    body,
	}
}

func newCTIDB(cnf config.VulnDictInterface) (ctidb.DB, error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, locked, err := ctidb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), ctidb.Option{})
	if err != nil {
		if locked {
			return nil, xerrors.Errorf("Failed to init cti DB. SQLite3: %s is locked. err: %w", cnf.GetSQLite3Path(), err)
		}
		return nil, xerrors.Errorf("Failed to init cti DB. DB Path: %s, err: %w", path, err)
	}
	return driver, nil
}
