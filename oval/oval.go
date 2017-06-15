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
	ver "github.com/knqyf263/go-deb-version"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
	"github.com/parnurzeal/gorequest"
)

// Client is the interface of OVAL client.
type Client interface {
	FillWithOval(r *models.ScanResult) error
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
	relatedDefs []ovalmodels.Definition, err error) {

	//TODO Health Check
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
			current, _ := ver.NewVersion(fmt.Sprintf("%s-%s",
				res.pack.Version, res.pack.Release))
			for _, def := range res.defs {
				for _, p := range def.AffectedPacks {
					affected, _ := ver.NewVersion(p.Version)
					if res.pack.Name != p.Name || !current.LessThan(affected) {
						continue
					}
					relatedDefs = append(relatedDefs, def)
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
