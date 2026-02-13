//go:build !scanner

package gost

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/hashicorp/go-version"
	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	gostmodels "github.com/vulsio/gost/models"
)

// Microsoft is Gost client for windows
type Microsoft struct {
	Base
}

// DetectCVEs fills cve information that has in Gost
func (ms Microsoft) DetectCVEs(r *models.ScanResult, _ bool) (nCVEs int, err error) {
	var applied, unapplied []string
	if r.WindowsKB != nil {
		applied = r.WindowsKB.Applied
		unapplied = r.WindowsKB.Unapplied
	}
	if ms.driver == nil {
		u, err := util.URLPathJoin(ms.baseURL, "microsoft", "kbs")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}

		content := map[string]any{"applied": applied, "unapplied": unapplied}
		var body []byte
		var errs []error
		var resp *http.Response
		f := func() error {
			req := gorequest.New().Post(u).SendStruct(content).Type("json")
			if config.Conf.Gost.TimeoutSecPerRequest > 0 {
				req = req.Timeout(time.Duration(config.Conf.Gost.TimeoutSecPerRequest) * time.Second)
			}
			resp, body, errs = req.EndBytes()
			if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
				return xerrors.Errorf("HTTP POST error. url: %s, resp: %v, err: %+v", u, resp, errs)
			}
			return nil
		}
		notify := func(err error, t time.Duration) {
			logging.Log.Warnf("Failed to HTTP POST. retrying in %f seconds. err: %+v", t.Seconds(), err)
		}
		if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
			return 0, xerrors.Errorf("HTTP Error: %w", err)
		}

		var r struct {
			Applied   []string `json:"applied"`
			Unapplied []string `json:"unapplied"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			return 0, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
		applied = r.Applied
		unapplied = r.Unapplied
	} else {
		applied, unapplied, err = ms.driver.GetExpandKB(applied, unapplied)
		if err != nil {
			return 0, xerrors.Errorf("Failed to detect CVEs. err: %w", err)
		}
	}

	var products []string
	if ms.driver == nil {
		u, err := util.URLPathJoin(ms.baseURL, "microsoft", "products")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}

		content := map[string]any{"release": r.Release, "kbs": append(applied, unapplied...)}
		var body []byte
		var errs []error
		var resp *http.Response
		f := func() error {
			req := gorequest.New().Post(u).SendStruct(content).Type("json")
			if config.Conf.Gost.TimeoutSecPerRequest > 0 {
				req = req.Timeout(time.Duration(config.Conf.Gost.TimeoutSecPerRequest) * time.Second)
			}
			resp, body, errs = req.EndBytes()
			if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
				return xerrors.Errorf("HTTP POST error. url: %s, resp: %v, err: %+v", u, resp, errs)
			}
			return nil
		}
		notify := func(err error, t time.Duration) {
			logging.Log.Warnf("Failed to HTTP POST. retrying in %f seconds. err: %+v", t.Seconds(), err)
		}
		if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
			return 0, xerrors.Errorf("HTTP Error: %w", err)
		}

		if err := json.Unmarshal(body, &products); err != nil {
			return 0, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
	} else {
		ps, err := ms.driver.GetRelatedProducts(r.Release, append(applied, unapplied...))
		if err != nil {
			return 0, xerrors.Errorf("Failed to detect CVEs. err: %w", err)
		}
		products = ps
	}

	m := map[string]struct{}{}
	for _, p := range products {
		m[p] = struct{}{}
	}
	for _, n := range []string{"Microsoft Edge (Chromium-based)", fmt.Sprintf("Microsoft Edge on %s", r.Release), fmt.Sprintf("Microsoft Edge (Chromium-based) in IE Mode on %s", r.Release), fmt.Sprintf("Microsoft Edge (EdgeHTML-based) on %s", r.Release)} {
		delete(m, n)
	}
	filtered := []string{r.Release}
	for _, p := range r.Packages {
		switch p.Name {
		case "Microsoft Edge":
			if ss := strings.Split(p.Version, "."); len(ss) > 0 {
				v, err := strconv.ParseInt(ss[0], 10, 8)
				if err != nil {
					continue
				}
				if v > 44 {
					filtered = append(filtered, "Microsoft Edge (Chromium-based)", fmt.Sprintf("Microsoft Edge on %s", r.Release), fmt.Sprintf("Microsoft Edge (Chromium-based) in IE Mode on %s", r.Release))
				} else {
					filtered = append(filtered, fmt.Sprintf("Microsoft Edge on %s", r.Release), fmt.Sprintf("Microsoft Edge (EdgeHTML-based) on %s", r.Release))
				}
			}
		default:
		}
	}
	filtered = unique(append(filtered, slices.Collect(maps.Keys(m))...))

	var cves map[string]gostmodels.MicrosoftCVE
	if ms.driver == nil {
		u, err := util.URLPathJoin(ms.baseURL, "microsoft", "filtered-cves")
		if err != nil {
			return 0, xerrors.Errorf("Failed to join URLPath. err: %w", err)
		}

		content := map[string]any{"products": filtered, "kbs": append(applied, unapplied...)}
		var body []byte
		var errs []error
		var resp *http.Response
		f := func() error {
			req := gorequest.New().Post(u).SendStruct(content).Type("json")
			if config.Conf.Gost.TimeoutSecPerRequest > 0 {
				req = req.Timeout(time.Duration(config.Conf.Gost.TimeoutSecPerRequest) * time.Second)
			}
			resp, body, errs = req.EndBytes()
			if 0 < len(errs) || resp == nil || resp.StatusCode != 200 {
				return xerrors.Errorf("HTTP POST error. url: %s, resp: %v, err: %+v", u, resp, errs)
			}
			return nil
		}
		notify := func(err error, t time.Duration) {
			logging.Log.Warnf("Failed to HTTP POST. retrying in %f seconds. err: %+v", t.Seconds(), err)
		}
		if err := backoff.RetryNotify(f, backoff.NewExponentialBackOff(), notify); err != nil {
			return 0, xerrors.Errorf("HTTP Error: %w", err)
		}

		if err := json.Unmarshal(body, &cves); err != nil {
			return 0, xerrors.Errorf("Failed to Unmarshal. body: %s, err: %w", body, err)
		}
	} else {
		cves, err = ms.driver.GetFilteredCvesMicrosoft(filtered, append(applied, unapplied...))
		if err != nil {
			return 0, xerrors.Errorf("Failed to detect CVEs. err: %w", err)
		}
	}

	for cveID, cve := range cves {
		v, err := ms.detect(r, cve, applied, unapplied)
		if err != nil {
			return 0, xerrors.Errorf("Failed to detect. err: %w", err)
		}
		if v == nil {
			continue
		}
		nCVEs++
		r.ScannedCves[cveID] = *v
	}
	return nCVEs, nil
}

func (ms Microsoft) detect(r *models.ScanResult, cve gostmodels.MicrosoftCVE, applied, unapplied []string) (*models.VulnInfo, error) {
	cve.Products = func() []gostmodels.MicrosoftProduct {
		var ps []gostmodels.MicrosoftProduct
		for _, p := range cve.Products {
			if len(p.KBs) == 0 {
				switch {
				case p.Name == r.Release:
					ps = append(ps, p)
				case strings.HasPrefix(p.Name, "Microsoft Edge"):
					ps = append(ps, p)
				default:
				}
				continue
			}

			p.KBs = func() []gostmodels.MicrosoftKB {
				var kbs []gostmodels.MicrosoftKB
				for _, kb := range p.KBs {
					if _, err := strconv.Atoi(kb.Article); err != nil {
						switch {
						case strings.HasPrefix(p.Name, "Microsoft Edge"):
							p, ok := r.Packages["Microsoft Edge"]
							if !ok {
								break
							}

							if kb.FixedBuild == "" {
								kbs = append(kbs, kb)
								break
							}

							vera, err := version.NewVersion(p.Version)
							if err != nil {
								kbs = append(kbs, kb)
								break
							}
							verb, err := version.NewVersion(kb.FixedBuild)
							if err != nil {
								kbs = append(kbs, kb)
								break
							}
							if vera.LessThan(verb) {
								kbs = append(kbs, kb)
							}
						default:
						}
					} else {
						if slices.Contains(applied, kb.Article) {
							return nil
						}
						if slices.Contains(unapplied, kb.Article) {
							kbs = append(kbs, kb)
						}
					}
				}
				return kbs
			}()
			if len(p.KBs) > 0 {
				ps = append(ps, p)
			}
		}
		return ps
	}()
	if len(cve.Products) == 0 {
		return nil, nil
	}

	cveCont, mitigations := ms.ConvertToModel(&cve)
	vinfo := models.VulnInfo{
		CveID:       cve.CveID,
		CveContents: models.NewCveContents(*cveCont),
		Mitigations: mitigations,
	}

	for _, p := range cve.Products {
		if len(p.KBs) == 0 {
			switch {
			case p.Name == r.Release:
				vinfo.AffectedPackages = append(vinfo.AffectedPackages, models.PackageFixStatus{
					Name:     p.Name,
					FixState: "unfixed",
				})
			case strings.HasPrefix(p.Name, "Microsoft Edge"):
				vinfo.AffectedPackages = append(vinfo.AffectedPackages, models.PackageFixStatus{
					Name:     "Microsoft Edge",
					FixState: "unknown",
				})
			default:
				return nil, xerrors.Errorf("unexpected product. expected: %q, actual: %q", []string{r.Release, "Microsoft Edge"}, p.Name)
			}
			continue
		}

		for _, kb := range p.KBs {
			if _, err := strconv.Atoi(kb.Article); err != nil {
				switch {
				case strings.HasPrefix(p.Name, "Microsoft Edge"):
					vinfo.AffectedPackages = append(vinfo.AffectedPackages, models.PackageFixStatus{
						Name: "Microsoft Edge",
						FixState: func() string {
							if func() bool {
								if kb.FixedBuild == "" {
									return true
								}

								if _, err := version.NewVersion(r.Packages["Microsoft Edge"].Version); err != nil {
									return true
								}

								if _, err := version.NewVersion(kb.FixedBuild); err != nil {
									return true
								}

								return false
							}() {
								return "unknown"
							}
							return "fixed"
						}(),
						FixedIn: kb.FixedBuild,
					})
				default:
					return nil, xerrors.Errorf("unexpected product. supported: %q, actual: %q", []string{"Microsoft Edge"}, p.Name)
				}
			} else {
				kbid := fmt.Sprintf("KB%s", kb.Article)
				vinfo.DistroAdvisories.AppendIfMissing(new(models.DistroAdvisory{
					AdvisoryID:  kbid,
					Description: "Microsoft Knowledge Base",
				}))
				if !slices.Contains(vinfo.WindowsKBFixedIns, kbid) {
					vinfo.WindowsKBFixedIns = append(vinfo.WindowsKBFixedIns, kbid)
				}
			}
		}
	}

	confs, err := func() (models.Confidences, error) {
		var cs models.Confidences

		if len(vinfo.WindowsKBFixedIns) > 0 {
			cs.AppendIfMissing(models.WindowsUpdateSearch)
		}

		for _, stat := range vinfo.AffectedPackages {
			switch stat.FixState {
			case "fixed", "unfixed":
				cs.AppendIfMissing(models.WindowsUpdateSearch)
			case "unknown":
				cs.AppendIfMissing(models.WindowsRoughMatch)
			default:
				return nil, xerrors.Errorf("unexpected fix state. expected: %q, actual: %q", []string{"fixed", "unfixed", "unknown"}, stat.FixState)
			}
		}

		if len(cs) == 0 {
			return nil, xerrors.New("confidences not found")
		}
		return cs, nil
	}()
	if err != nil {
		return nil, xerrors.Errorf("Failed to detect confidences. err: %w", err)
	}
	vinfo.Confidences = confs

	return &vinfo, nil
}

// ConvertToModel converts gost model to vuls model
func (ms Microsoft) ConvertToModel(cve *gostmodels.MicrosoftCVE) (*models.CveContent, []models.Mitigation) {
	slices.SortFunc(cve.Products, func(i, j gostmodels.MicrosoftProduct) int {
		return cmp.Compare(i.ScoreSet.Vector, j.ScoreSet.Vector)
	})

	p := slices.MaxFunc(cve.Products, func(a, b gostmodels.MicrosoftProduct) int {
		va, erra := strconv.ParseFloat(a.ScoreSet.BaseScore, 64)
		vb, errb := strconv.ParseFloat(b.ScoreSet.BaseScore, 64)
		if erra != nil {
			if errb != nil {
				return 0
			}
			return -1
		}
		if errb != nil {
			return +1
		}
		return cmp.Compare(va, vb)
	})

	var mitigations []models.Mitigation
	if cve.Mitigation != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Mitigation,
			URL:            cve.URL,
		})
	}
	if cve.Workaround != "" {
		mitigations = append(mitigations, models.Mitigation{
			CveContentType: models.Microsoft,
			Mitigation:     cve.Workaround,
			URL:            cve.URL,
		})
	}

	return &models.CveContent{
		Type:    models.Microsoft,
		CveID:   cve.CveID,
		Title:   cve.Title,
		Summary: cve.Description,
		Cvss3Score: func() float64 {
			v, err := strconv.ParseFloat(p.ScoreSet.BaseScore, 64)
			if err != nil {
				return 0.0
			}
			return v
		}(),
		Cvss3Vector:   p.ScoreSet.Vector,
		Cvss3Severity: p.Severity,
		Published:     cve.PublishDate,
		LastModified:  cve.LastUpdateDate,
		SourceLink:    cve.URL,
		Optional: func() map[string]string {
			if 0 < len(cve.ExploitStatus) {
				// TODO: CVE-2020-0739
				// "exploit_status": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely;Older Software Release:Exploitation Less Likely;DOS:N/A",
				return map[string]string{"exploit": cve.ExploitStatus}
			}
			return nil
		}(),
	}, mitigations
}
