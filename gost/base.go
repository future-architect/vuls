package gost

import (
	"fmt"
	"net/http"

	cnf "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/knqyf263/gost/db"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

// Base is a base struct
type Base struct {
}

// FillCVEsWithRedHat fills cve information that has in Gost
func (b Base) FillCVEsWithRedHat(driver db.DB, r *models.ScanResult) error {
	return RedHat{}.fillFixed(driver, r)
}

// CheckHTTPHealth do health check
func (b Base) CheckHTTPHealth() error {
	if !cnf.Conf.Gost.IsFetchViaHTTP() {
		return nil
	}

	url := fmt.Sprintf("%s/health", cnf.Conf.Gost.URL)
	var errs []error
	var resp *http.Response
	resp, _, errs = gorequest.New().Get(url).End()
	//  resp, _, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
	//  resp, _, errs = gorequest.New().Proxy(api.httpProxy).Get(url).End()
	if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
		return xerrors.Errorf("Failed to connect to gost server. url: %s, errs: %w", url, errs)
	}
	return nil
}

// CheckIfGostFetched checks if oval entries are in DB by family, release.
func (b Base) CheckIfGostFetched(driver db.DB, osFamily string) (fetched bool, err error) {
	//TODO
	return true, nil
}

// CheckIfGostFresh checks if oval entries are fresh enough
func (b Base) CheckIfGostFresh(driver db.DB, osFamily string) (ok bool, err error) {
	//TODO
	return true, nil
}
