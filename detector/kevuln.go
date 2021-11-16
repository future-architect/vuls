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
	"golang.org/x/xerrors"

	kevulndb "github.com/MaineK00n/go-kev/db"
	kevulnmodels "github.com/MaineK00n/go-kev/models"
)

// FillWithKEVuln :
func FillWithKEVuln(r *models.ScanResult, cnf config.KEVulnConf) error {
	if cnf.IsFetchViaHTTP() {
		var cveIDs []string
		for cveID := range r.ScannedCves {
			cveIDs = append(cveIDs, cveID)
		}
		prefix, err := util.URLPathJoin(cnf.GetURL(), "cves")
		if err != nil {
			return err
		}
		responses, err := getKEVulnsViaHTTP(cveIDs, prefix)
		if err != nil {
			return err
		}
		for _, res := range responses {
			kevulns := []kevulnmodels.KEVuln{}
			if err := json.Unmarshal([]byte(res.json), &kevulns); err != nil {
				return err
			}

			alerts := []models.Alert{}
			if len(kevulns) > 0 {
				alerts = append(alerts, models.Alert{
					Title: "Known Exploited Vulnerabilities Catalog",
					URL:   "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
					Team:  "cisa",
				})
			}

			v, ok := r.ScannedCves[res.request.cveID]
			if ok {
				v.AlertDict.CISA = alerts
			}
			r.ScannedCves[res.request.cveID] = v
		}
	} else {
		driver, locked, err := newKEVulnDB(&cnf)
		if locked {
			return xerrors.Errorf("SQLite3 is locked: %s", cnf.GetSQLite3Path())
		} else if err != nil {
			return err
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
			vs, err := driver.GetKEVulnByCveID(cveID)
			if err != nil {
				return err
			}
			if len(vs) == 0 {
				continue
			}
			kevulns := ConvertToModelsKEVuln(vs)

			alerts := []models.Alert{}
			if len(kevulns) > 0 {
				alerts = append(alerts, models.Alert{
					Title: "Known Exploited Vulnerabilities Catalog",
					URL:   "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
					Team:  "cisa",
				})
			}

			vuln.AlertDict.CISA = alerts
			r.ScannedCves[cveID] = vuln
		}
	}
	return nil
}

type kevulnResponse struct {
	request kevulnRequest
	json    string
}

func getKEVulnsViaHTTP(cveIDs []string, urlPrefix string) (
	responses []kevulnResponse, err error) {
	nReq := len(cveIDs)
	reqChan := make(chan kevulnRequest, nReq)
	resChan := make(chan kevulnResponse, nReq)
	errChan := make(chan error, nReq)
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, cveID := range cveIDs {
			reqChan <- kevulnRequest{
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
				httpGetKEVuln(url, req, resChan, errChan)
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
			return nil, xerrors.New("Timeout Fetching KEVuln")
		}
	}
	if len(errs) != 0 {
		return nil, xerrors.Errorf("Failed to fetch KEVuln. err: %w", errs)
	}
	return
}

type kevulnRequest struct {
	cveID string
}

func httpGetKEVuln(url string, req kevulnRequest, resChan chan<- kevulnResponse, errChan chan<- error) {
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

	resChan <- kevulnResponse{
		request: req,
		json:    body,
	}
}

// ConvertToModelsKEVuln converts kevuln model to vuls model
func ConvertToModelsKEVuln(vs []kevulnmodels.KEVuln) (vulns []models.KEVuln) {
	for _, v := range vs {
		vuln := models.KEVuln{
			Title:       v.Title,
			Description: v.Description,
		}
		vulns = append(vulns, vuln)
	}
	return vulns
}

func newKEVulnDB(cnf config.VulnDictInterface) (driver kevulndb.DB, locked bool, err error) {
	if cnf.IsFetchViaHTTP() {
		return nil, false, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	if driver, locked, err = kevulndb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), kevulndb.Option{}); err != nil {
		if locked {
			return nil, true, xerrors.Errorf("kevulnDB is locked. err: %w", err)
		}
		return nil, false, err
	}
	return driver, false, nil
}
