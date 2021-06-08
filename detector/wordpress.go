// +build !scanner

package detector

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/errof"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	version "github.com/hashicorp/go-version"
	"golang.org/x/xerrors"
)

//WpCveInfos is for wpscan json
type WpCveInfos struct {
	ReleaseDate  string `json:"release_date"`
	ChangelogURL string `json:"changelog_url"`
	// Status        string `json:"status"`
	LatestVersion string `json:"latest_version"`
	LastUpdated   string `json:"last_updated"`
	// Popular         bool        `json:"popular"`
	Vulnerabilities []WpCveInfo `json:"vulnerabilities"`
	Error           string      `json:"error"`
}

//WpCveInfo is for wpscan json
type WpCveInfo struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	VulnType   string     `json:"vuln_type"`
	References References `json:"references"`
	FixedIn    string     `json:"fixed_in"`
}

//References is for wpscan json
type References struct {
	URL     []string `json:"url"`
	Cve     []string `json:"cve"`
	Secunia []string `json:"secunia"`
}

// DetectWordPressCves access to wpscan and fetch scurity alerts and then set to the given ScanResult.
// https://wpscan.com/
func detectWordPressCves(r *models.ScanResult, cnf config.WpScanConf) (int, error) {
	if len(r.WordPressPackages) == 0 {
		return 0, nil
	}
	// Core
	ver := strings.Replace(r.WordPressPackages.CoreVersion(), ".", "", -1)
	if ver == "" {
		return 0, errof.New(errof.ErrFailedToAccessWpScan,
			fmt.Sprintf("Failed to get WordPress core version."))
	}
	url := fmt.Sprintf("https://wpscan.com/api/v3/wordpresses/%s", ver)
	wpVinfos, err := wpscan(url, ver, cnf.Token, true)
	if err != nil {
		return 0, err
	}

	// Themes
	themes := r.WordPressPackages.Themes()
	if !cnf.DetectInactive {
		themes = removeInactives(themes)
	}
	for _, p := range themes {
		url := fmt.Sprintf("https://wpscan.com/api/v3/themes/%s", p.Name)
		candidates, err := wpscan(url, p.Name, cnf.Token, false)
		if err != nil {
			return 0, err
		}
		vulns := detect(p, candidates)
		wpVinfos = append(wpVinfos, vulns...)
	}

	// Plugins
	plugins := r.WordPressPackages.Plugins()
	if !cnf.DetectInactive {
		plugins = removeInactives(plugins)
	}
	for _, p := range plugins {
		url := fmt.Sprintf("https://wpscan.com/api/v3/plugins/%s", p.Name)
		candidates, err := wpscan(url, p.Name, cnf.Token, false)
		if err != nil {
			return 0, err
		}
		vulns := detect(p, candidates)
		wpVinfos = append(wpVinfos, vulns...)
	}

	for _, wpVinfo := range wpVinfos {
		if vinfo, ok := r.ScannedCves[wpVinfo.CveID]; ok {
			vinfo.CveContents[models.WpScan] = wpVinfo.CveContents[models.WpScan]
			vinfo.VulnType = wpVinfo.VulnType
			vinfo.Confidences = append(vinfo.Confidences, wpVinfo.Confidences...)
			vinfo.WpPackageFixStats = append(vinfo.WpPackageFixStats, wpVinfo.WpPackageFixStats...)
			r.ScannedCves[wpVinfo.CveID] = vinfo
		} else {
			r.ScannedCves[wpVinfo.CveID] = wpVinfo
		}
	}
	return len(wpVinfos), nil
}

func wpscan(url, name, token string, isCore bool) (vinfos []models.VulnInfo, err error) {
	body, err := httpRequest(url, token)
	if err != nil {
		return nil, err
	}
	if body == "" {
		logging.Log.Debugf("wpscan.com response body is empty. URL: %s", url)
	}
	if isCore {
		name = "core"
	}
	return convertToVinfos(name, body)
}

func detect(installed models.WpPackage, candidates []models.VulnInfo) (vulns []models.VulnInfo) {
	for _, v := range candidates {
		for _, fixstat := range v.WpPackageFixStats {
			ok, err := match(installed.Version, fixstat.FixedIn)
			if err != nil {
				logging.Log.Warnf("Failed to compare versions %s installed: %s, fixedIn: %s, v: %+v",
					installed.Name, installed.Version, fixstat.FixedIn, v)
				// continue scanning
				continue
			}
			if ok {
				vulns = append(vulns, v)
				logging.Log.Debugf("Affected: %s installed: %s, fixedIn: %s",
					installed.Name, installed.Version, fixstat.FixedIn)
			} else {
				logging.Log.Debugf("Not affected: %s : %s, fixedIn: %s",
					installed.Name, installed.Version, fixstat.FixedIn)
			}
		}
	}
	return
}

func match(installedVer, fixedIn string) (bool, error) {
	v1, err := version.NewVersion(installedVer)
	if err != nil {
		return false, err
	}
	v2, err := version.NewVersion(fixedIn)
	if err != nil {
		return false, err
	}
	return v1.LessThan(v2), nil
}

func convertToVinfos(pkgName, body string) (vinfos []models.VulnInfo, err error) {
	if body == "" {
		return
	}
	// "pkgName" : CVE Detailed data
	pkgnameCves := map[string]WpCveInfos{}
	if err = json.Unmarshal([]byte(body), &pkgnameCves); err != nil {
		return nil, xerrors.Errorf("Failed to unmarshal %s. err: %w", body, err)
	}

	for _, v := range pkgnameCves {
		vs := extractToVulnInfos(pkgName, v.Vulnerabilities)
		vinfos = append(vinfos, vs...)
	}
	return vinfos, nil
}

func extractToVulnInfos(pkgName string, cves []WpCveInfo) (vinfos []models.VulnInfo) {
	for _, vulnerability := range cves {
		var cveIDs []string

		if len(vulnerability.References.Cve) == 0 {
			cveIDs = append(cveIDs, fmt.Sprintf("WPVDBID-%s", vulnerability.ID))
		}
		for _, cveNumber := range vulnerability.References.Cve {
			cveIDs = append(cveIDs, "CVE-"+cveNumber)
		}

		var refs []models.Reference
		for _, url := range vulnerability.References.URL {
			refs = append(refs, models.Reference{
				Link: url,
			})
		}

		for _, cveID := range cveIDs {
			vinfos = append(vinfos, models.VulnInfo{
				CveID: cveID,
				CveContents: models.NewCveContents(
					models.CveContent{
						Type:         models.WpScan,
						CveID:        cveID,
						Title:        vulnerability.Title,
						References:   refs,
						Published:    vulnerability.CreatedAt,
						LastModified: vulnerability.UpdatedAt,
					},
				),
				VulnType: vulnerability.VulnType,
				Confidences: []models.Confidence{
					models.WpScanMatch,
				},
				WpPackageFixStats: []models.WpPackageFixStatus{{
					Name:    pkgName,
					FixedIn: vulnerability.FixedIn,
				}},
			})
		}
	}
	return
}

func httpRequest(url, token string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	defer cancel()
	if err != nil {
		return "", errof.New(errof.ErrFailedToAccessWpScan,
			fmt.Sprintf("Failed to access to wpscan.com. err: %s", err))
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=%s", token))
	client, err := util.GetHTTPClient(config.Conf.HTTPProxy)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", errof.New(errof.ErrFailedToAccessWpScan,
			fmt.Sprintf("Failed to access to wpscan.com. err: %s", err))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errof.New(errof.ErrFailedToAccessWpScan,
			fmt.Sprintf("Failed to access to wpscan.com. err: %s", err))
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return string(body), nil
	} else if resp.StatusCode == 404 {
		// This package is not in wpscan
		return "", nil
	} else if resp.StatusCode == 429 {
		return "", errof.New(errof.ErrWpScanAPILimitExceeded,
			fmt.Sprintf("wpscan.com API limit exceeded: %+v", resp.Status))
	} else {
		logging.Log.Warnf("wpscan.com unknown status code: %+v", resp.Status)
		return "", nil
	}
}

func removeInactives(pkgs models.WordPressPackages) (removed models.WordPressPackages) {
	for _, p := range pkgs {
		if p.Status == "inactive" {
			continue
		}
		removed = append(removed, p)
	}
	return removed
}
