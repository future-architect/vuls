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

type ovalResult struct {
	entries []defPacks
}

type defPacks struct {
	def                       ovalmodels.Definition
	actuallyAffectedPackNames map[string]bool
}

func (e defPacks) toPackStatuses(family string, packs models.Packages) (ps models.PackageStatuses) {
	switch family {
	case config.Ubuntu:
		packNotFixedYet := map[string]bool{}
		for _, p := range e.def.AffectedPacks {
			packNotFixedYet[p.Name] = p.NotFixedYet
		}
		for k := range e.actuallyAffectedPackNames {
			ps = append(ps, models.PackageStatus{
				Name:        k,
				NotFixedYet: packNotFixedYet[k],
			})
		}

	case config.CentOS, config.Debian:
		// There are many packages that has been fixed in RedHat, but not been fixed in CentOS
		for name := range e.actuallyAffectedPackNames {
			pack, ok := packs[name]
			if !ok {
				util.Log.Warnf("Faild to find in Package list: %s", name)
				return
			}

			ovalPackVer := ""
			for _, p := range e.def.AffectedPacks {
				if p.Name == name {
					ovalPackVer = p.Version
					break
				}
			}
			if ovalPackVer == "" {
				util.Log.Warnf("Faild to find in Oval Package list: %s", name)
				return
			}

			if pack.NewVersion == "" {
				// compare version: installed vs oval
				vera := rpmver.NewVersion(fmt.Sprintf("%s-%s", pack.Version, pack.Release))
				verb := rpmver.NewVersion(ovalPackVer)
				notFixedYet := false
				if vera.LessThan(verb) {
					notFixedYet = true
				}
				ps = append(ps, models.PackageStatus{
					Name:        name,
					NotFixedYet: notFixedYet,
				})
			} else {
				// compare version: newVer vs oval
				packNewVer := fmt.Sprintf("%s-%s", pack.NewVersion, pack.NewRelease)
				vera := rpmver.NewVersion(packNewVer)
				verb := rpmver.NewVersion(ovalPackVer)
				notFixedYet := false
				if vera.LessThan(verb) {
					notFixedYet = true
				}
				ps = append(ps, models.PackageStatus{
					Name:        name,
					NotFixedYet: notFixedYet,
				})
			}
		}

	default:
		for k := range e.actuallyAffectedPackNames {
			ps = append(ps, models.PackageStatus{
				Name: k,
			})
		}
	}

	return
}

func (e *ovalResult) upsert(def ovalmodels.Definition, packName string) (upserted bool) {
	for i, entry := range e.entries {
		if entry.def.DefinitionID == def.DefinitionID {
			e.entries[i].actuallyAffectedPackNames[packName] = true
			return true
		}
	}
	e.entries = append(e.entries, defPacks{
		def: def,
		actuallyAffectedPackNames: map[string]bool{packName: true},
	})
	return false
}

type request struct {
	pack models.Package
}

type response struct {
	pack *models.Package
	defs []ovalmodels.Definition
}

// getDefsByPackNameViaHTTP fetches OVAL information via HTTP
func getDefsByPackNameViaHTTP(r *models.ScanResult) (
	relatedDefs ovalResult, err error) {

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

					if p.NotFixedYet {
						relatedDefs.upsert(def, p.Name)
						continue
					}

					if less, err := lessThan(r.Family, *res.pack, p); err != nil {
						util.Log.Debugf("Failed to parse versions: %s", err)
						util.Log.Debugf("%#v\n%#v", *res.pack, p)
					} else if less {
						relatedDefs.upsert(def, p.Name)
					}
				}
			}
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return relatedDefs, fmt.Errorf("Timeout Fetching OVAL")
		}
	}
	if len(errs) != 0 {
		return relatedDefs, fmt.Errorf("Failed to fetch OVAL. err: %v", errs)
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

func getDefsByPackNameFromOvalDB(family, osRelease string,
	installedPacks models.Packages) (relatedDefs ovalResult, err error) {

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
	for _, installedPack := range installedPacks {
		definitions, err := ovaldb.GetByPackName(osRelease, installedPack.Name)
		if err != nil {
			return relatedDefs, fmt.Errorf("Failed to get %s OVAL info by package name: %v", family, err)
		}
		for _, def := range definitions {
			for _, ovalPack := range def.AffectedPacks {
				if installedPack.Name != ovalPack.Name {
					continue
				}

				if ovalPack.NotFixedYet {
					relatedDefs.upsert(def, installedPack.Name)
					continue
				}

				less, err := lessThan(family, installedPack, ovalPack)
				if err != nil {
					util.Log.Debugf("Failed to parse versions: %s", err)
					util.Log.Debugf("%#v\n%#v", installedPack, ovalPack)
				} else if less {
					relatedDefs.upsert(def, installedPack.Name)
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
	case config.RedHat, config.CentOS, config.Oracle, config.SUSEEnterpriseServer:
		vera := rpmver.NewVersion(fmt.Sprintf("%s-%s", packA.Version, packA.Release))
		verb := rpmver.NewVersion(packB.Version)
		return vera.LessThan(verb), nil
	default:
		util.Log.Errorf("Not implemented yet: %s", family)
	}
	return false, fmt.Errorf("Package version comparison not supported: %s", family)
}
