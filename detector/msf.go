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
	metasploitdb "github.com/vulsio/go-msfdb/db"
	metasploitmodels "github.com/vulsio/go-msfdb/models"
	metasploitlog "github.com/vulsio/go-msfdb/utils"
)

// goMetasploitDBClient is a DB Driver
type goMetasploitDBClient struct {
	driver  metasploitdb.DB
	baseURL string
}

// closeDB close a DB connection
func (client goMetasploitDBClient) closeDB() error {
	if client.driver == nil {
		return nil
	}
	return client.driver.CloseDB()
}

func newGoMetasploitDBClient(cnf config.VulnDictInterface, o logging.LogOpts) (*goMetasploitDBClient, error) {
	if err := metasploitlog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return nil, xerrors.Errorf("Failed to set go-msfdb logger. err: %w", err)
	}

	db, err := newMetasploitDB(cnf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to newMetasploitDB. err: %w", err)
	}
	return &goMetasploitDBClient{driver: db, baseURL: cnf.GetURL()}, nil
}

// FillWithMetasploit fills metasploit module information that has in module
func FillWithMetasploit(r *models.ScanResult, cnf config.MetasploitConf, logOpts logging.LogOpts) (nMetasploitCve int, err error) {
	client, err := newGoMetasploitDBClient(&cnf, logOpts)
	if err != nil {
		return 0, xerrors.Errorf("Failed to newGoMetasploitDBClient. err: %w", err)
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	if client.driver == nil {
		var cveIDs []string
		for cveID := range r.ScannedCves {
			cveIDs = append(cveIDs, cveID)
		}
		prefix, err := util.URLPathJoin(client.baseURL, "cves")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}
		responses, err := getMetasploitsViaHTTP(cveIDs, prefix)
		if err != nil {
			return 0, xerrors.Errorf("Failed to get Metasploits via HTTP. err: %w", err)
		}
		for _, res := range responses {
			msfs := []metasploitmodels.Metasploit{}
			if err := json.Unmarshal([]byte(res.json), &msfs); err != nil {
				return 0, xerrors.Errorf("Failed to unmarshal json. err: %w", err)
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
		for cveID, vuln := range r.ScannedCves {
			if cveID == "" {
				continue
			}
			ms, err := client.driver.GetModuleByCveID(cveID)
			if err != nil {
				return 0, xerrors.Errorf("Failed to get Metasploits by CVE-ID. err: %w", err)
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

func newMetasploitDB(cnf config.VulnDictInterface) (metasploitdb.DB, error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, locked, err := metasploitdb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), metasploitdb.Option{})
	if err != nil {
		if locked {
			return nil, xerrors.Errorf("Failed to init metasploit DB. SQLite3: %s is locked. err: %w", cnf.GetSQLite3Path(), err)
		}
		return nil, xerrors.Errorf("Failed to init metasploit DB. DB Path: %s, err: %w", path, err)
	}
	return driver, nil
}
