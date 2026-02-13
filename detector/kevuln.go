//go:build !scanner

package detector

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	kevulndb "github.com/vulsio/go-kev/db"
	kevulnlog "github.com/vulsio/go-kev/utils"
)

// goKEVulnDBClient is a DB Driver
type goKEVulnDBClient struct {
	driver  kevulndb.DB
	baseURL string
}

// closeDB close a DB connection
func (client goKEVulnDBClient) closeDB() error {
	if client.driver == nil {
		return nil
	}
	return client.driver.CloseDB()
}

func newGoKEVulnDBClient(cnf config.VulnDictInterface, o logging.LogOpts) (*goKEVulnDBClient, error) {
	if err := kevulnlog.SetLogger(o.LogToFile, o.LogDir, o.Debug, o.LogJSON); err != nil {
		return nil, xerrors.Errorf("Failed to set go-kev logger. err: %w", err)
	}

	db, err := newKEVulnDB(cnf)
	if err != nil {
		return nil, xerrors.Errorf("Failed to newKEVulnDB. err: %w", err)
	}
	return &goKEVulnDBClient{driver: db, baseURL: cnf.GetURL()}, nil
}

// FillWithKEVuln :
func FillWithKEVuln(r *models.ScanResult, cnf config.KEVulnConf, logOpts logging.LogOpts) error {
	client, err := newGoKEVulnDBClient(&cnf, logOpts)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.closeDB(); err != nil {
			logging.Log.Errorf("Failed to close DB. err: %+v", err)
		}
	}()

	nKEV := 0
	if client.driver == nil {
		var cveIDs []string
		for cveID := range r.ScannedCves {
			cveIDs = append(cveIDs, cveID)
		}
		prefix, err := util.URLPathJoin(client.baseURL, "cves")
		if err != nil {
			return err
		}
		responses, err := getKEVulnsViaHTTP(cveIDs, prefix)
		if err != nil {
			return err
		}
		for _, res := range responses {
			var kev kevulndb.Response
			if err := json.Unmarshal([]byte(res.json), &kev); err != nil {
				return err
			}

			kevs := func() []models.KEV {
				ks := make([]models.KEV, 0, len(kev.CISA)+len(kev.VulnCheck))
				for _, k := range kev.CISA {
					ks = append(ks, models.KEV{
						Type:                       models.CISAKEVType,
						VendorProject:              k.VendorProject,
						Product:                    k.Product,
						VulnerabilityName:          k.VulnerabilityName,
						ShortDescription:           k.ShortDescription,
						RequiredAction:             k.RequiredAction,
						KnownRansomwareCampaignUse: k.KnownRansomwareCampaignUse,
						DateAdded:                  k.DateAdded,
						DueDate: func() *time.Time {
							if k.DueDate.Equal(time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)) {
								return nil
							}
							return &k.DueDate
						}(),
						CISA: &models.CISAKEV{
							Note: k.Notes,
						},
					})
				}
				for _, k := range kev.VulnCheck {
					ks = append(ks, models.KEV{
						Type:                       models.VulnCheckKEVType,
						VendorProject:              k.VendorProject,
						Product:                    k.Product,
						VulnerabilityName:          k.Name,
						ShortDescription:           k.Description,
						RequiredAction:             k.RequiredAction,
						KnownRansomwareCampaignUse: k.KnownRansomwareCampaignUse,
						DateAdded:                  k.DateAdded,
						DueDate:                    k.DueDate,
						VulnCheck: &models.VulnCheckKEV{
							XDB: func() []models.VulnCheckXDB {
								xdb := make([]models.VulnCheckXDB, 0, len(k.VulnCheckXDB))
								for _, x := range k.VulnCheckXDB {
									xdb = append(xdb, models.VulnCheckXDB{
										XDBID:       x.XDBID,
										XDBURL:      x.XDBURL,
										DateAdded:   x.DateAdded,
										ExploitType: x.ExploitType,
										CloneSSHURL: x.CloneSSHURL,
									})
								}
								return xdb
							}(),
							ReportedExploitation: func() []models.VulnCheckReportedExploitation {
								es := make([]models.VulnCheckReportedExploitation, 0, len(k.VulnCheckReportedExploitation))
								for _, e := range k.VulnCheckReportedExploitation {
									es = append(es, models.VulnCheckReportedExploitation{
										URL:       e.URL,
										DateAdded: e.DateAdded,
									})
								}
								return es
							}(),
						},
					})
				}
				return ks
			}()

			v, ok := r.ScannedCves[res.request.cveID]
			if ok {
				v.KEVs = kevs
				nKEV++
			}
			r.ScannedCves[res.request.cveID] = v
		}
	} else {
		for cveID, vuln := range r.ScannedCves {
			if cveID == "" {
				continue
			}
			kev, err := client.driver.GetKEVByCveID(cveID)
			if err != nil {
				return xerrors.Errorf("Failed to get kev by %s", cveID)
			}
			if len(kev.CISA) == 0 && len(kev.VulnCheck) == 0 {
				continue
			}

			vuln.KEVs = func() []models.KEV {
				ks := make([]models.KEV, 0, len(kev.CISA)+len(kev.VulnCheck))
				for _, k := range kev.CISA {
					ks = append(ks, models.KEV{
						Type:                       models.CISAKEVType,
						VendorProject:              k.VendorProject,
						Product:                    k.Product,
						VulnerabilityName:          k.VulnerabilityName,
						ShortDescription:           k.ShortDescription,
						RequiredAction:             k.RequiredAction,
						KnownRansomwareCampaignUse: k.KnownRansomwareCampaignUse,
						DateAdded:                  k.DateAdded,
						DueDate: func() *time.Time {
							if k.DueDate.Equal(time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC)) {
								return nil
							}
							return &k.DueDate
						}(),
						CISA: &models.CISAKEV{
							Note: k.Notes,
						},
					})
				}
				for _, k := range kev.VulnCheck {
					ks = append(ks, models.KEV{
						Type:                       models.VulnCheckKEVType,
						VendorProject:              k.VendorProject,
						Product:                    k.Product,
						VulnerabilityName:          k.Name,
						ShortDescription:           k.Description,
						RequiredAction:             k.RequiredAction,
						KnownRansomwareCampaignUse: k.KnownRansomwareCampaignUse,
						DateAdded:                  k.DateAdded,
						DueDate:                    k.DueDate,
						VulnCheck: &models.VulnCheckKEV{
							XDB: func() []models.VulnCheckXDB {
								xdb := make([]models.VulnCheckXDB, 0, len(k.VulnCheckXDB))
								for _, x := range k.VulnCheckXDB {
									xdb = append(xdb, models.VulnCheckXDB{
										XDBID:       x.XDBID,
										XDBURL:      x.XDBURL,
										DateAdded:   x.DateAdded,
										ExploitType: x.ExploitType,
										CloneSSHURL: x.CloneSSHURL,
									})
								}
								return xdb
							}(),
							ReportedExploitation: func() []models.VulnCheckReportedExploitation {
								es := make([]models.VulnCheckReportedExploitation, 0, len(k.VulnCheckReportedExploitation))
								for _, e := range k.VulnCheckReportedExploitation {
									es = append(es, models.VulnCheckReportedExploitation{
										URL:       e.URL,
										DateAdded: e.DateAdded,
									})
								}
								return es
							}(),
						},
					})
				}
				return ks
			}()

			nKEV++
			r.ScannedCves[cveID] = vuln
		}
	}

	logging.Log.Infof("%s: Known Exploited Vulnerabilities are detected for %d CVEs", r.FormatServerName(), nKEV)
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
				httpGetKEVuln(url, req, resChan, errChan)
			}
		}
	}

	var timeout <-chan time.Time
	if config.Conf.KEVuln.TimeoutSec > 0 {
		timeout = time.After(time.Duration(config.Conf.KEVuln.TimeoutSec) * time.Second)
	}
	var errs []error
	for range nReq {
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
		req := gorequest.New().Get(url)
		if config.Conf.KEVuln.TimeoutSecPerRequest > 0 {
			req = req.Timeout(time.Duration(config.Conf.KEVuln.TimeoutSecPerRequest) * time.Second)
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

	resChan <- kevulnResponse{
		request: req,
		json:    body,
	}
}

func newKEVulnDB(cnf config.VulnDictInterface) (kevulndb.DB, error) {
	if cnf.IsFetchViaHTTP() {
		return nil, nil
	}
	path := cnf.GetURL()
	if cnf.GetType() == "sqlite3" {
		path = cnf.GetSQLite3Path()
	}
	driver, err := kevulndb.NewDB(cnf.GetType(), path, cnf.GetDebugSQL(), kevulndb.Option{})
	if err != nil {
		if errors.Is(err, kevulndb.ErrDBLocked) {
			return nil, xerrors.Errorf("Failed to init kevuln DB. SQLite3: %s is locked. err: %w", cnf.GetSQLite3Path(), err)
		}
		return nil, xerrors.Errorf("Failed to init kevuln DB. DB Path: %s, err: %w", path, err)
	}
	return driver, nil
}
