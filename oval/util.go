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

package oval

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/kotakanbe/goval-dictionary/db"
	ovallog "github.com/kotakanbe/goval-dictionary/log"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
	"github.com/parnurzeal/gorequest"
)

type request struct {
	pack models.Package
}

type response struct {
	pack *models.Package
	defs []ovalmodels.Definition
}

// getDefsByPackNameViaHTTP fetches OVAL information via HTTP
func getDefsByPackNameViaHTTP(r *models.ScanResult) (
	relatedDefs []ovalmodels.Definition, err error) {

	reqChan := make(chan request, len(r.Packages))
	resChan := make(chan response, len(r.Packages))
	errChan := make(chan error, len(r.Packages))
	defer close(reqChan)
	defer close(resChan)
	defer close(errChan)

	go func() {
		for _, pack := range r.Packages {
			reqChan <- request{
				pack: pack,
			}
		}
	}()

	concurrency := 10
	tasks := util.GenWorkers(concurrency)
	for range r.Packages {
		tasks <- func() {
			select {
			case req := <-reqChan:
				url, err := util.URLPathJoin(
					config.Conf.OvalDBURL,
					"packs",
					r.Family,
					r.Release,
					req.pack.Name,
				)
				if err != nil {
					errChan <- err
				} else {
					util.Log.Debugf("HTTP Request to %s", url)
					httpGet(url, &req.pack, resChan, errChan)
				}
			}
		}
	}

	timeout := time.After(2 * 60 * time.Second)
	var errs []error
	for range r.Packages {
		select {
		case res := <-resChan:
			for _, def := range res.defs {
				for _, p := range def.AffectedPacks {
					if res.pack.Name != p.Name {
						continue
					}
					if less, err := lessThan(r.Family, *res.pack, p); err != nil {
						if !p.NotFixedYet {
							util.Log.Debugf("Failed to parse versions: %s", err)
							util.Log.Debugf("%#v\n%#v", *res.pack, p)
						}
					} else if less {
						relatedDefs = append(relatedDefs, def)
					}
				}
			}
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return nil, fmt.Errorf("Timeout Fetching OVAL")
		}
	}
	if len(errs) != 0 {
		return nil, fmt.Errorf("Failed to fetch OVAL. err: %v", errs)
	}
	return
}

func httpGet(url string, pack *models.Package, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	count, retryMax := 0, 3
	f := func() (err error) {
		//  resp, body, errs = gorequest.New().SetDebug(config.Conf.Debug).Get(url).End()
		resp, body, errs = gorequest.New().Get(url).End()
		if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
			count++
			if count == retryMax {
				return nil
			}
			return fmt.Errorf("HTTP GET error: %v, url: %s, resp: %v",
				errs, url, resp)
		}
		return nil
	}
	notify := func(err error, t time.Duration) {
		util.Log.Warnf("Failed to HTTP GET. retrying in %s seconds. err: %s", t, err)
	}
	err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify)
	if err != nil {
		errChan <- fmt.Errorf("HTTP Error %s", err)
		return
	}
	if count == retryMax {
		errChan <- fmt.Errorf("HRetry count exceeded")
		return
	}

	defs := []ovalmodels.Definition{}
	if err := json.Unmarshal([]byte(body), &defs); err != nil {
		errChan <- fmt.Errorf("Failed to Unmarshall. body: %s, err: %s",
			body, err)
		return
	}
	resChan <- response{
		pack: pack,
		defs: defs,
	}
}

func getPackages(r *models.ScanResult, d *ovalmodels.Definition) (names []string) {
	for _, affectedPack := range d.AffectedPacks {
		names = append(names, affectedPack.Name)
	}
	return
}

func getDefsByPackNameFromOvalDB(family, osRelease string,
	packs models.Packages) (relatedDefs []ovalmodels.Definition, err error) {

	ovallog.Initialize(config.Conf.LogDir)
	path := config.Conf.OvalDBURL
	if config.Conf.OvalDBType == "sqlite3" {
		path = config.Conf.OvalDBPath
	}
	util.Log.Debugf("Open oval-dictionary db (%s): %s", config.Conf.OvalDBType, path)

	var ovaldb db.DB
	if ovaldb, err = db.NewDB(
		family,
		config.Conf.OvalDBType,
		path,
		config.Conf.DebugSQL,
	); err != nil {
		return
	}
	defer ovaldb.CloseDB()
	for _, pack := range packs {
		definitions, err := ovaldb.GetByPackName(osRelease, pack.Name)
		if err != nil {
			return nil, fmt.Errorf("Failed to get %s OVAL info by package name: %v", family, err)
		}
		for _, def := range definitions {
			for _, p := range def.AffectedPacks {
				if pack.Name != p.Name {
					continue
				}
				if less, err := lessThan(family, pack, p); err != nil {
					if !p.NotFixedYet {
						util.Log.Debugf("Failed to parse versions: %s", err)
						util.Log.Debugf("%#v\n%#v", pack, p)
					}
				} else if less {
					relatedDefs = append(relatedDefs, def)
				}
			}
		}
	}
	return
}

func lessThan(family string, packA models.Package, packB ovalmodels.Package) (bool, error) {
	switch family {
	case config.Debian, config.Ubuntu:
		vera, err := debver.NewVersion(packA.Version)
		if err != nil {
			return false, err
		}
		verb, err := debver.NewVersion(packB.Version)
		if err != nil {
			return false, err
		}
		return vera.LessThan(verb), nil
	case config.RedHat, config.CentOS, config.Oracle:
		vera := rpmver.NewVersion(fmt.Sprintf("%s-%s", packA.Version, packA.Release))
		verb := rpmver.NewVersion(packB.Version)
		return vera.LessThan(verb), nil
	}
	return false, fmt.Errorf("Package version comparison not supported: %s", family)
}
