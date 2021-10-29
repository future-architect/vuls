//go:build !scanner
// +build !scanner

package detector

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/parnurzeal/gorequest"
	metasploitdb "github.com/vulsio/go-msfdb/db"
	metasploitmodels "github.com/vulsio/go-msfdb/models"
	"golang.org/x/xerrors"
)

// FillWithMetasploit fills metasploit module information that has in module
func FillWithMetasploit(r *models.ScanResult, cnf config.MetasploitConf) (nMetasploitCve int, err error) {
	if cnf.IsFetchViaHTTP() {
		var cveIDs []string
		for cveID := range r.ScannedCves {
			cveIDs = append(cveIDs, cveID)
		}
		prefix, err := util.URLPathJoin(cnf.GetURL(), "cves")
		if err != nil {
			return 0, err
		}
		responses, err := getMetasploitsViaHTTP(cveIDs, prefix)
		if err != nil {
			return 0, err
		}
		for _, res := range responses {
			msfs := []metasploitmodels.Metasploit{}
			if err := json.Unmarshal([]byte(res.json), &msfs); err != nil {
				return 0, err
			}
			metasploits := ConvertToModelsMsf(msfs)
			v, ok := r.ScannedCves[res.request.cveID]
			if ok {
				v.Metasploits = metasploits
			}
			r.ScannedCves[res.request.cveID] = v
			nMetasploitCve++
		}
	} else {
		driver, locked, err := newMetasploitDB(&cnf)
		if locked {
			return 0, xerrors.Errorf("SQLite3 is locked: %s", cnf.GetSQLite3Path())
		} else if err != nil {
			return 0, err
		}
		defer func() {
			if err := driver.CloseDB(); err != nil {
				logging.Log.Errorf("Failed to close DB. err: %+v", err)
			}
		}()

		for cveID, vuln := range r.ScannedCves {
			if cveID == "" {
				continue
			}
			ms, err := driver.GetModuleByCveID(cveID)
			if err != nil {
				return 0, err
			}
			if len(ms) == 0 {
				continue
			}
			modules := ConvertToModelsMsf(ms)
			vuln.Metasploits = modules
			r.ScannedCves[cveID] = vuln
			nMetasploitCve++
		}
	}
	return nMetasploitCve, nil
}

type metasploitResponse struct {
	request metasploitRequest
	json    string
}

func getMetasploitsViaHTTP(cveIDs []string, urlPrefix string) (
	responses []metasploitResponse, err error) {
	nReq := len(cveIDs)
	reqChan := make(chan metasploitRequest, nReq)
	resChan := make(chan metasploitResponse, nReq)
	errChan := make(chan error, nReq)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, cveID := range cveIDs {
			reqChan <- metasploitRequest{
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
				httpGetMetasploit(url, req, resChan, errChan)
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
			return nil, xerrors.New("Timeout Fetching Metasploit")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch Metasploit. err: %w", errs)
	}
	return
}

type metasploitRequest struct {
	cveID string
}

func httpGetMetasploit(url string, req metasploitRequest, resChan chan<- metasploitResponse, errChan chan<- error) {
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

	resChan <- metasploitResponse{
		request: req,
		json:    body,
	}
}

// ConvertToModelsMsf converts metasploit model to vuls model
func ConvertToModelsMsf(ms []metasploitmodels.Metasploit) (modules []models.Metasploit) {
	for _, m := range ms {
		var links []string
		if 0 < len(m.References) {
			for _, u := range m.References {
				links = append(links, u.Link)
			}
		}
		module := models.Metasploit{
			Name:        m.Name,
			Title:       m.Title,
			Description: m.Description,
			URLs:        links,
		}
		modules = append(modules, module)
	}
	return modules
}

func newMetasploitDB(cnf config.VulnDictInterface) (driver metasploitdb.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	if driver, locked, err = metasploitdb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), metasploitdb.Option{}); err != nil {
		if locked {
			return nil, true, xerrors.Errorf("metasploitDB is locked. err: %w", err)
		}
		return nil, false, err
	}
	return driver, false, nil
}
