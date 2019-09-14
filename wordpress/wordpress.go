package wordpress

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	version "github.com/hashicorp/go-version"
	"golang.org/x/xerrors"
)

//WpCveInfos is for wpvulndb's json
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

//WpCveInfo is for wpvulndb's json
type WpCveInfo struct {
	ID        int    `json:"id"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// PublishedDate string     `json:"published_date"`
	VulnType   string     `json:"vuln_type"`
	References References `json:"references"`
	FixedIn    string     `json:"fixed_in"`
}

//References is for wpvulndb's json
type References struct {
	URL     []string `json:"url"`
	Cve     []string `json:"cve"`
	Secunia []string `json:"secunia"`
}

// FillWordPress access to wpvulndb and fetch scurity alerts and then set to the given ScanResult.
// https://wpvulndb.com/
func FillWordPress(r *models.ScanResult, token string) (int, error) {
	// Core
	ver := strings.Replace(r.WordPressPackages.CoreVersion(), ".", "", -1)
	if ver == "" {
		return 0, xerrors.New("Failed to get WordPress core version")
	}
	url := fmt.Sprintf("https://wpvulndb.com/api/v3/wordpresses/%s", ver)
	body, err := httpRequest(url, token)
	if err != nil {
		return 0, err
	}
	if body == "" {
		util.Log.Warnf("A result of REST access is empty: %s", url)
	}
	wpVinfos, err := convertToVinfos(models.WPCore, body)
	if err != nil {
		return 0, err
	}

	//TODO add a flag ignore inactive plugin or themes such as -wp-ignore-inactive flag to cmd line option or config.toml

	// Themes
	for _, p := range r.WordPressPackages.Themes() {
		url := fmt.Sprintf("https://wpvulndb.com/api/v3/themes/%s", p.Name)
		body, err := httpRequest(url, token)
		if err != nil {
			return 0, err
		}
		if body == "" {
			continue
		}

		templateVinfos, err := convertToVinfos(p.Name, body)
		if err != nil {
			return 0, err
		}

		for _, v := range templateVinfos {
			for _, fixstat := range v.WpPackageFixStats {
				pkg, ok := r.WordPressPackages.Find(fixstat.Name)
				if !ok {
					continue
				}
				ok, err := match(pkg.Version, fixstat.FixedIn)
				if err != nil {
					return 0, xerrors.Errorf("Not a semantic versioning: %w", err)
				}
				if ok {
					wpVinfos = append(wpVinfos, v)
					util.Log.Infof("[match] %s installed: %s, fixedIn: %s", pkg.Name, pkg.Version, fixstat.FixedIn)
				} else {
					util.Log.Debugf("[miss] %s installed: %s, fixedIn: %s", pkg.Name, pkg.Version, fixstat.FixedIn)
				}
			}
		}
	}

	// Plugins
	for _, p := range r.WordPressPackages.Plugins() {
		url := fmt.Sprintf("https://wpvulndb.com/api/v3/plugins/%s", p.Name)
		body, err := httpRequest(url, token)
		if err != nil {
			return 0, err
		}
		if body == "" {
			continue
		}

		pluginVinfos, err := convertToVinfos(p.Name, body)
		if err != nil {
			return 0, err
		}

		for _, v := range pluginVinfos {
			for _, fixstat := range v.WpPackageFixStats {
				pkg, ok := r.WordPressPackages.Find(fixstat.Name)
				if !ok {
					continue
				}
				ok, err := match(pkg.Version, fixstat.FixedIn)
				if err != nil {
					return 0, xerrors.Errorf("Not a semantic versioning: %w", err)
				}
				if ok {
					wpVinfos = append(wpVinfos, v)
					//TODO Debugf
					util.Log.Infof("[match] %s installed: %s, fixedIn: %s", pkg.Name, pkg.Version, fixstat.FixedIn)
				} else {
					//TODO Debugf
					util.Log.Infof("[miss] %s installed: %s, fixedIn: %s", pkg.Name, pkg.Version, fixstat.FixedIn)
				}
			}
		}
	}

	for _, wpVinfo := range wpVinfos {
		if vinfo, ok := r.ScannedCves[wpVinfo.CveID]; ok {
			vinfo.CveContents[models.WPVulnDB] = wpVinfo.CveContents[models.WPVulnDB]
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
			cveIDs = append(cveIDs, fmt.Sprintf("WPVDBID-%d", vulnerability.ID))
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
						Type:       models.WPVulnDB,
						CveID:      cveID,
						Title:      vulnerability.Title,
						References: refs,
					},
				),
				VulnType: vulnerability.VulnType,
				Confidences: []models.Confidence{
					models.WPVulnDBMatch,
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
	retry := 1
	util.Log.Debugf("%s", url)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Token token=%s", token))
loop:
	resp, err := new(http.Client).Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		return string(body), nil
	} else if resp.StatusCode == 404 {
		// This package is not in WPVulnDB
		return "", nil
	} else if resp.StatusCode == 429 && retry <= 3 {
		// 429 Too Many Requests
		util.Log.Debugf("sleep %d min(s): %s", retry, resp.Status)
		time.Sleep(time.Duration(retry) * time.Minute)
		retry++
		goto loop
	}
	return "", err
}
