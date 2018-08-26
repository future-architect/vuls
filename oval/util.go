/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"regexp"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/kotakanbe/goval-dictionary/db"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
	"github.com/parnurzeal/gorequest"
)

type ovalResult struct {
	entries []defPacks
}

type defPacks struct {
	def ovalmodels.Definition

	// BinaryPackageName : NotFixedYet
	actuallyAffectedPackNames map[string]bool
}

func (e defPacks) toPackStatuses() (ps models.PackageStatuses) {
	for name, notFixedYet := range e.actuallyAffectedPackNames {
		ps = append(ps, models.PackageStatus{
			Name:        name,
			NotFixedYet: notFixedYet,
		})
	}
	return
}

func (e *ovalResult) upsert(def ovalmodels.Definition, packName string, notFixedYet bool) (upserted bool) {
	// alpine's entry is empty since Alpine secdb is not OVAL format
	if def.DefinitionID != "" {
		for i, entry := range e.entries {
			if entry.def.DefinitionID == def.DefinitionID {
				e.entries[i].actuallyAffectedPackNames[packName] = notFixedYet
				return true
			}
		}
	}
	e.entries = append(e.entries, defPacks{
		def:                       def,
		actuallyAffectedPackNames: map[string]bool{packName: notFixedYet},
	})

	return false
}

type request struct {
	packName          string
	versionRelease    string
	NewVersionRelease string
	binaryPackNames   []string
	isSrcPack         bool
}

type response struct {
	request request
	defs    []ovalmodels.Definition
}

// getDefsByPackNameViaHTTP fetches OVAL information via HTTP
func getDefsByPackNameViaHTTP(r *models.ScanResult) (
	relatedDefs ovalResult, err error) {

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
				packName:          pack.Name,
				versionRelease:    pack.FormatVer(),
				NewVersionRelease: pack.FormatVer(),
				isSrcPack:         false,
			}
		}
		for _, pack := range r.SrcPackages {
			reqChan <- request{
				packName:        pack.Name,
				binaryPackNames: pack.BinaryNames,
				versionRelease:  pack.Version,
				isSrcPack:       true,
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
					config.Conf.OvalDBURL,
					"packs",
					r.Family,
					r.Release,
					req.packName,
				)
				if err != nil {
					errChan <- err
				} else {
					util.Log.Debugf("HTTP Request to %s", url)
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
			for _, def := range res.defs {
				affected, notFixedYet := isOvalDefAffected(def, res.request, r.Family, r.RunningKernel)
				if !affected {
					continue
				}

				if res.request.isSrcPack {
					for _, n := range res.request.binaryPackNames {
						relatedDefs.upsert(def, n, false)
					}
				} else {
					relatedDefs.upsert(def, res.request.packName, notFixedYet)
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

func httpGet(url string, req request, resChan chan<- response, errChan chan<- error) {
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
		request: req,
		defs:    defs,
	}
}

func getDefsByPackNameFromOvalDB(r *models.ScanResult) (relatedDefs ovalResult, err error) {
	path := config.Conf.OvalDBURL
	if config.Conf.OvalDBType == "sqlite3" {
		path = config.Conf.OvalDBPath
	}
	util.Log.Debugf("Open oval-dictionary db (%s): %s", config.Conf.OvalDBType, path)

	var ovaldb db.DB
	if ovaldb, _, err = db.NewDB(r.Family, config.Conf.OvalDBType,
		path, config.Conf.DebugSQL); err != nil {
		return
	}
	defer ovaldb.CloseDB()

	requests := []request{}
	for _, pack := range r.Packages {
		requests = append(requests, request{
			packName:          pack.Name,
			versionRelease:    pack.FormatVer(),
			NewVersionRelease: pack.FormatNewVer(),
			isSrcPack:         false,
		})
	}
	for _, pack := range r.SrcPackages {
		requests = append(requests, request{
			packName:        pack.Name,
			binaryPackNames: pack.BinaryNames,
			versionRelease:  pack.Version,
			isSrcPack:       true,
		})
	}

	for _, req := range requests {
		definitions, err := ovaldb.GetByPackName(r.Release, req.packName)
		if err != nil {
			return relatedDefs, fmt.Errorf("Failed to get %s OVAL info by package name: %v", r.Family, err)
		}
		for _, def := range definitions {
			affected, notFixedYet := isOvalDefAffected(def, req, r.Family, r.RunningKernel)
			if !affected {
				continue
			}

			if req.isSrcPack {
				for _, n := range req.binaryPackNames {
					relatedDefs.upsert(def, n, false)
				}
			} else {
				relatedDefs.upsert(def, req.packName, notFixedYet)
			}
		}
	}
	return
}

func major(version string) string {
	ss := strings.SplitN(version, ":", 2)
	ver := ""
	if len(ss) == 1 {
		ver = ss[0]
	} else {
		ver = ss[1]
	}
	return ver[0:strings.Index(ver, ".")]
}

func isOvalDefAffected(def ovalmodels.Definition, req request, family string, running models.Kernel) (affected, notFixedYet bool) {
	for _, ovalPack := range def.AffectedPacks {
		if req.packName != ovalPack.Name {
			continue
		}

		if running.Release != "" {
			switch family {
			case config.RedHat, config.CentOS:
				// For kernel related packages, ignore OVAL information with different major versions
				if _, ok := kernelRelatedPackNames[ovalPack.Name]; ok {
					if major(ovalPack.Version) != major(running.Release) {
						continue
					}
				}
			}
		}

		if ovalPack.NotFixedYet {
			return true, true
		}

		less, err := lessThan(family, req.versionRelease, ovalPack)
		if err != nil {
			util.Log.Debugf("Failed to parse versions: %s, Ver: %#v, OVAL: %#v, DefID: %s",
				err, req.versionRelease, ovalPack, def.DefinitionID)
			return false, false
		}

		if less {
			if req.isSrcPack {
				// Unable to judge whether fixed or not fixed of src package(Ubuntu, Debian)
				return true, false
			}
			if req.NewVersionRelease == "" {
				return true, true
			}

			// compare version: newVer vs oval
			less, err := lessThan(family, req.NewVersionRelease, ovalPack)
			if err != nil {
				util.Log.Debugf("Failed to parse versions: %s, NewVer: %#v, OVAL: %#v, DefID: %s",
					err, req.NewVersionRelease, ovalPack, def.DefinitionID)
				return false, false
			}
			return true, less
		}
	}
	return false, false
}

func lessThan(family, versionRelease string, packB ovalmodels.Package) (bool, error) {
	switch family {
	case config.Debian, config.Ubuntu:
		vera, err := debver.NewVersion(versionRelease)
		if err != nil {
			return false, err
		}
		verb, err := debver.NewVersion(packB.Version)
		if err != nil {
			return false, err
		}
		return vera.LessThan(verb), nil
	case config.Oracle, config.SUSEEnterpriseServer, config.Alpine:
		vera := rpmver.NewVersion(versionRelease)
		verb := rpmver.NewVersion(packB.Version)
		return vera.LessThan(verb), nil
	case config.RedHat, config.CentOS: // TODO: Suport config.Scientific
		rea := regexp.MustCompile(`\.[es]l(\d+)(?:_\d+)?(?:\.centos)?`)
		reb := regexp.MustCompile(`\.el(\d+)(?:_\d+)?`)
		vera := rpmver.NewVersion(rea.ReplaceAllString(versionRelease, ".el$1"))
		verb := rpmver.NewVersion(reb.ReplaceAllString(packB.Version, ".el$1"))
		return vera.LessThan(verb), nil
	default:
		util.Log.Errorf("Not implemented yet: %s", family)
	}
	return false, fmt.Errorf("Package version comparison not supported: %s", family)
}
