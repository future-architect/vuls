// +build !scanner

package oval

import (
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	apkver "github.com/knqyf263/go-apk-version"
	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/kotakanbe/goval-dictionary/db"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
)

type ovalResult struct {
	entries []defPacks
}

type defPacks struct {
	def ovalmodels.Definition

	// BinaryPackageName : NotFixedYet
	binpkgFixstat map[string]fixStat
}

type fixStat struct {
	notFixedYet bool
	fixedIn     string
	isSrcPack   bool
	srcPackName string
}

func (e defPacks) toPackStatuses() (ps models.PackageFixStatuses) {
	for name, stat := range e.binpkgFixstat {
		ps = append(ps, models.PackageFixStatus{
			Name:        name,
			NotFixedYet: stat.notFixedYet,
			FixedIn:     stat.fixedIn,
		})
	}
	return
}

func (e *ovalResult) upsert(def ovalmodels.Definition, packName string, fstat fixStat) (upserted bool) {
	// alpine's entry is empty since Alpine secdb is not OVAL format
	if def.DefinitionID != "" {
		for i, entry := range e.entries {
			if entry.def.DefinitionID == def.DefinitionID {
				e.entries[i].binpkgFixstat[packName] = fstat
				return true
			}
		}
	}
	e.entries = append(e.entries, defPacks{
		def: def,
		binpkgFixstat: map[string]fixStat{
			packName: fstat,
		},
	})

	return false
}

func (e *ovalResult) Sort() {
	sort.SliceStable(e.entries, func(i, j int) bool {
		return e.entries[i].def.DefinitionID < e.entries[j].def.DefinitionID
	})
}

type request struct {
	packName          string
	versionRelease    string
	newVersionRelease string
	arch              string
	binaryPackNames   []string
	isSrcPack         bool
	modularityLabel   string // RHEL 8 or later only
}

type response struct {
	request request
	defs    []ovalmodels.Definition
}

// getDefsByPackNameViaHTTP fetches OVAL information via HTTP
func getDefsByPackNameViaHTTP(r *models.ScanResult, url string) (relatedDefs ovalResult, err error) {

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
				newVersionRelease: pack.FormatVer(),
				isSrcPack:         false,
				arch:              pack.Arch,
			}
		}
		for _, pack := range r.SrcPackages {
			reqChan <- request{
				packName:        pack.Name,
				binaryPackNames: pack.BinaryNames,
				versionRelease:  pack.Version,
				isSrcPack:       true,
				// arch:            pack.Arch,
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
					url,
					"packs",
					r.Family,
					r.Release,
					req.packName,
				)
				if err != nil {
					errChan <- err
				} else {
					logging.Log.Debugf("HTTP Request to %s", url)
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
				affected, notFixedYet, fixedIn, err := isOvalDefAffected(def, res.request, r.Family, r.RunningKernel, r.EnabledDnfModules)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				if !affected {
					continue
				}

				if res.request.isSrcPack {
					for _, n := range res.request.binaryPackNames {
						fs := fixStat{
							srcPackName: res.request.packName,
							isSrcPack:   true,
							notFixedYet: notFixedYet,
							fixedIn:     fixedIn,
						}
						relatedDefs.upsert(def, n, fs)
					}
				} else {
					fs := fixStat{
						notFixedYet: notFixedYet,
						fixedIn:     fixedIn,
					}
					relatedDefs.upsert(def, res.request.packName, fs)
				}
			}
		case err := <-errChan:
			errs = append(errs, err)
		case <-timeout:
			return relatedDefs, xerrors.New("Timeout Fetching OVAL")
		}
	}
	if len(errs) != 0 {
		return relatedDefs, xerrors.Errorf("Failed to detect OVAL. err: %w", errs)
	}
	return
}

func httpGet(url string, req request, resChan chan<- response, errChan chan<- error) {
	var body string
	var errs []error
	var resp *http.Response
	count, retryMax := 0, 3
	f := func() (err error) {
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
		errChan <- xerrors.New("HRetry count exceeded")
		return
	}

	defs := []ovalmodels.Definition{}
	if err := json.Unmarshal([]byte(body), &defs); err != nil {
		errChan <- xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		return
	}
	resChan <- response{
		request: req,
		defs:    defs,
	}
}

func getDefsByPackNameFromOvalDB(driver db.DB, r *models.ScanResult) (relatedDefs ovalResult, err error) {
	requests := []request{}
	for _, pack := range r.Packages {
		requests = append(requests, request{
			packName:          pack.Name,
			versionRelease:    pack.FormatVer(),
			newVersionRelease: pack.FormatNewVer(),
			arch:              pack.Arch,
			isSrcPack:         false,
		})
	}
	for _, pack := range r.SrcPackages {
		requests = append(requests, request{
			packName:        pack.Name,
			binaryPackNames: pack.BinaryNames,
			versionRelease:  pack.Version,
			arch:            pack.Arch,
			isSrcPack:       true,
		})
	}

	ovalFamily, err := GetFamilyInOval(r.Family)
	if err != nil {
		return relatedDefs, err
	}

	for _, req := range requests {
		definitions, err := driver.GetByPackName(ovalFamily, r.Release, req.packName, req.arch)
		if err != nil {
			return relatedDefs, xerrors.Errorf("Failed to get %s OVAL info by package: %#v, err: %w", r.Family, req, err)
		}
		for _, def := range definitions {
			affected, notFixedYet, fixedIn, err := isOvalDefAffected(def, req, ovalFamily, r.RunningKernel, r.EnabledDnfModules)
			if err != nil {
				return relatedDefs, xerrors.Errorf("Failed to exec isOvalAffected. err: %w", err)
			}
			if !affected {
				continue
			}

			if req.isSrcPack {
				for _, binName := range req.binaryPackNames {
					fs := fixStat{
						notFixedYet: false,
						isSrcPack:   true,
						fixedIn:     fixedIn,
						srcPackName: req.packName,
					}
					relatedDefs.upsert(def, binName, fs)
				}
			} else {
				fs := fixStat{
					notFixedYet: notFixedYet,
					fixedIn:     fixedIn,
				}
				relatedDefs.upsert(def, req.packName, fs)
			}
		}
	}
	return
}

func isOvalDefAffected(def ovalmodels.Definition, req request, family string, running models.Kernel, enabledMods []string) (affected, notFixedYet bool, fixedIn string, err error) {
	for _, ovalPack := range def.AffectedPacks {
		if req.packName != ovalPack.Name {
			continue
		}

		switch family {
		case constant.Oracle, constant.Amazon:
			if ovalPack.Arch == "" {
				logging.Log.Infof("Arch is needed to detect Vulns for Amazon and Oracle Linux, but empty. You need refresh OVAL maybe. oval: %#v, defID: %s", ovalPack, def.DefinitionID)
				continue
			}
		}

		if ovalPack.Arch != "" && req.arch != ovalPack.Arch {
			continue
		}

		// https://github.com/aquasecurity/trivy/pull/745
		if strings.Contains(req.versionRelease, ".ksplice1.") != strings.Contains(ovalPack.Version, ".ksplice1.") {
			continue
		}

		isModularityLabelEmptyOrSame := false
		if ovalPack.ModularityLabel != "" {
			for _, mod := range enabledMods {
				if mod == ovalPack.ModularityLabel {
					isModularityLabelEmptyOrSame = true
					break
				}
			}
		} else {
			isModularityLabelEmptyOrSame = true
		}
		if !isModularityLabelEmptyOrSame {
			continue
		}

		if running.Release != "" {
			switch family {
			case constant.RedHat, constant.CentOS, constant.Rocky, constant.Oracle:
				// For kernel related packages, ignore OVAL information with different major versions
				if _, ok := kernelRelatedPackNames[ovalPack.Name]; ok {
					if util.Major(ovalPack.Version) != util.Major(running.Release) {
						continue
					}
				}
			}
		}

		if ovalPack.NotFixedYet {
			return true, true, ovalPack.Version, nil
		}

		// Compare between the installed version vs the version in OVAL
		less, err := lessThan(family, req.versionRelease, ovalPack)
		if err != nil {
			logging.Log.Debugf("Failed to parse versions: %s, Ver: %#v, OVAL: %#v, DefID: %s",
				err, req.versionRelease, ovalPack, def.DefinitionID)
			return false, false, ovalPack.Version, nil
		}
		if less {
			if req.isSrcPack {
				// Unable to judge whether fixed or not-fixed of src package(Ubuntu, Debian)
				return true, false, ovalPack.Version, nil
			}

			// If the version of installed is less than in OVAL
			switch family {
			case constant.RedHat,
				constant.Amazon,
				constant.SUSEEnterpriseServer,
				constant.Debian,
				constant.Ubuntu,
				constant.Raspbian,
				constant.Oracle:
				// Use fixed state in OVAL for these distros.
				return true, false, ovalPack.Version, nil
			}

			// But CentOS/Rocky can't judge whether fixed or unfixed.
			// Because fixed state in RHEL OVAL is different.
			// So, it have to be judged version comparison.

			// `offline` or `fast` scan mode can't get a updatable version.
			// In these mode, the blow field was set empty.
			// Vuls can not judge fixed or unfixed.
			if req.newVersionRelease == "" {
				return true, false, ovalPack.Version, nil
			}

			// compare version: newVer vs oval
			less, err := lessThan(family, req.newVersionRelease, ovalPack)
			if err != nil {
				logging.Log.Debugf("Failed to parse versions: %s, NewVer: %#v, OVAL: %#v, DefID: %s",
					err, req.newVersionRelease, ovalPack, def.DefinitionID)
				return false, false, ovalPack.Version, nil
			}
			return true, less, ovalPack.Version, nil
		}
	}
	return false, false, "", nil
}

func lessThan(family, newVer string, packInOVAL ovalmodels.Package) (bool, error) {
	switch family {
	case constant.Debian,
		constant.Ubuntu,
		constant.Raspbian:
		vera, err := debver.NewVersion(newVer)
		if err != nil {
			return false, err
		}
		verb, err := debver.NewVersion(packInOVAL.Version)
		if err != nil {
			return false, err
		}
		return vera.LessThan(verb), nil

	case constant.Alpine:
		vera, err := apkver.NewVersion(newVer)
		if err != nil {
			return false, err
		}
		verb, err := apkver.NewVersion(packInOVAL.Version)
		if err != nil {
			return false, err
		}
		return vera.LessThan(verb), nil

	case constant.Oracle,
		constant.SUSEEnterpriseServer,
		constant.Amazon:
		vera := rpmver.NewVersion(newVer)
		verb := rpmver.NewVersion(packInOVAL.Version)
		return vera.LessThan(verb), nil

	case constant.RedHat,
		constant.CentOS,
		constant.Rocky:
		vera := rpmver.NewVersion(rhelDownStreamOSVersionToRHEL(newVer))
		verb := rpmver.NewVersion(rhelDownStreamOSVersionToRHEL(packInOVAL.Version))
		return vera.LessThan(verb), nil

	default:
		return false, xerrors.Errorf("Not implemented yet: %s", family)
	}
}

var rhelDownStreamOSVerPattern = regexp.MustCompile(`\.[es]l(\d+)(?:_\d+)?(?:\.(centos|rocky))?`)

func rhelDownStreamOSVersionToRHEL(ver string) string {
	return rhelDownStreamOSVerPattern.ReplaceAllString(ver, ".el$1")
}

// NewOVALClient returns a client for OVAL database
func NewOVALClient(family string, cnf config.GovalDictConf) (Client, error) {
	switch family {
	case constant.Debian, constant.Raspbian:
		return NewDebian(&cnf), nil
	case constant.Ubuntu:
		return NewUbuntu(&cnf), nil
	case constant.RedHat:
		return NewRedhat(&cnf), nil
	case constant.CentOS:
		return NewCentOS(&cnf), nil
	case constant.Rocky:
		return NewRocky(&cnf), nil
	case constant.Oracle:
		return NewOracle(&cnf), nil
	case constant.SUSEEnterpriseServer:
		// TODO other suse family
		return NewSUSE(&cnf), nil
	case constant.Alpine:
		return NewAlpine(&cnf), nil
	case constant.Amazon:
		return NewAmazon(&cnf), nil
	case constant.FreeBSD, constant.Windows:
		return nil, nil
	case constant.ServerTypePseudo:
		return nil, nil
	default:
		if family == "" {
			return nil, xerrors.New("Probably an error occurred during scanning. Check the error message")
		}
		return nil, xerrors.Errorf("OVAL for %s is not implemented yet", family)
	}
}

// GetFamilyInOval returns the OS family name in OVAL
// For example, CentOS/Rocky uses Red Hat's OVAL, so return 'redhat'
func GetFamilyInOval(familyInScanResult string) (string, error) {
	switch familyInScanResult {
	case constant.Debian, constant.Raspbian:
		return constant.Debian, nil
	case constant.Ubuntu:
		return constant.Ubuntu, nil
	case constant.RedHat, constant.CentOS, constant.Rocky:
		return constant.RedHat, nil
	case constant.Oracle:
		return constant.Oracle, nil
	case constant.SUSEEnterpriseServer:
		// TODO other suse family
		return constant.SUSEEnterpriseServer, nil
	case constant.Alpine:
		return constant.Alpine, nil
	case constant.Amazon:
		return constant.Amazon, nil
	case constant.FreeBSD, constant.Windows:
		return "", nil
	case constant.ServerTypePseudo:
		return "", nil
	default:
		if familyInScanResult == "" {
			return "", xerrors.New("Probably an error occurred during scanning. Check the error message")
		}
		return "", xerrors.Errorf("OVAL for %s is not implemented yet", familyInScanResult)
	}

}
