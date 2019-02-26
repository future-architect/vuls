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

package wordpress

//WpCveInfos is for wpvulndb's json
type WpCveInfos struct {
	ReleaseDate  string `json:"release_date"`
	ChangelogURL string `json:"changelog_url"`
	// Status        string `json:"status"`
	LatestVersion string `json:"latest_version"`
	LastUpdated   string `json:"last_updated"`
	// Popular         bool        `json:"popular"`
	Vulnerabilities []WpCveInfo `json:"vulnerabilities"`
	// Error           string      `json:"error"`
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

// func detectWpCore(l *base) (vinfos []models.VulnInfo, err error) {
// 	cmd := fmt.Sprintf("sudo -u %s -i -- %s core version --path=%s",
// 		l.ServerInfo.WpUser,
// 		l.ServerInfo.WpCmdPath,
// 		l.ServerInfo.WpDocRoot)

// 	var r execResult
// 	if r = exec(l.ServerInfo, cmd, noSudo); !r.isSuccess() {
// 		return nil, fmt.Errorf("%s", cmd)
// 	}
// 	ver := strings.Replace(strings.TrimSpace(r.Stdout), ".", "", -1)
// 	if len(ver) == 0 {
// 		return nil, fmt.Errorf("Failed to get WordPress core version")
// 	}

// 	url := fmt.Sprintf("https://wpvulndb.com/api/v3/wordpresses/%s", ver)
// 	var body []byte
// 	if body, err = httpRequest(l, models.WpPackage{Name: "core"}, url); err != nil {
// 		return nil, err
// 	}
// 	if vinfos, err = coreConvertVinfos(string(body)); err != nil {
// 		return nil, err
// 	}
// 	return vinfos, nil
// }

// func coreConvertVinfos(stdout string) (vinfos []models.VulnInfo, err error) {
// 	data := map[string]wordpress.WpCveInfos{}
// 	if err = json.Unmarshal([]byte(stdout), &data); err != nil {
// 		var jsonError wordpress.WpCveInfos
// 		if err = json.Unmarshal([]byte(stdout), &jsonError); err != nil {
// 			return nil, err
// 		}
// 	}
// 	for _, e := range data {
// 		if len(e.Vulnerabilities) == 0 {
// 			continue
// 		}
// 		for _, vulnerability := range e.Vulnerabilities {
// 			if len(vulnerability.References.Cve) == 0 {
// 				continue
// 			}
// 			notFixedYet := false
// 			if len(vulnerability.FixedIn) == 0 {
// 				notFixedYet = true
// 			}
// 			var cveIDs []string
// 			for _, cveNumber := range vulnerability.References.Cve {
// 				cveIDs = append(cveIDs, "CVE-"+cveNumber)
// 			}

// 			for _, cveID := range cveIDs {
// 				vinfos = append(vinfos, models.VulnInfo{
// 					CveID: cveID,
// 					CveContents: models.NewCveContents(
// 						models.CveContent{
// 							CveID: cveID,
// 							Title: vulnerability.Title,
// 						},
// 					),
// 					AffectedPackages: models.PackageStatuses{
// 						{
// 							NotFixedYet: notFixedYet,
// 						},
// 					},
// 				})
// 			}
// 		}
// 	}
// 	return vinfos, nil
// }

// func detectWpTheme(l *base) (vinfos []models.VulnInfo, err error) {
// 	cmd := fmt.Sprintf("sudo -u %s -i -- %s theme list --path=%s --format=json",
// 		l.ServerInfo.WpUser,
// 		l.ServerInfo.WpCmdPath,
// 		l.ServerInfo.WpDocRoot)

// 	var themes []models.WpPackage
// 	var r execResult
// 	if r = exec(l.ServerInfo, cmd, noSudo); !r.isSuccess() {
// 		return nil, fmt.Errorf("%s", cmd)
// 	}
// 	if err = json.Unmarshal([]byte(r.Stdout), &themes); err != nil {
// 		return nil, err
// 	}

// 	for _, theme := range themes {
// 		url := fmt.Sprintf("https://wpvulndb.com/api/v3/themes/%s", theme.Name)
// 		var body []byte
// 		if body, err = httpRequest(l, theme, url); err != nil {
// 			return nil, err
// 		}
// 		tmpVinfos, err := contentConvertVinfos(string(body), theme)
// 		if err != nil {
// 			return nil, err
// 		}
// 		vinfos = append(vinfos, tmpVinfos...)
// 	}
// 	return vinfos, nil
// }

// func detectWpPlugin(l *base) (vinfos []models.VulnInfo, err error) {
// 	cmd := fmt.Sprintf("sudo -u %s -i -- %s plugin list --path=%s --format=json",
// 		l.ServerInfo.WpUser,
// 		l.ServerInfo.WpCmdPath,
// 		l.ServerInfo.WpDocRoot)

// 	var plugins []models.WpPackage
// 	r := exec(l.ServerInfo, cmd, noSudo)
// 	if r.isSuccess() {
// 		if err = json.Unmarshal([]byte(r.Stdout), &plugins); err != nil {
// 			return nil, err
// 		}
// 	}
// 	if !r.isSuccess() {
// 		return nil, fmt.Errorf("%s", cmd)
// 	}

// 	for _, plugin := range plugins {
// 		url := fmt.Sprintf("https://wpvulndb.com/api/v3/plugins/%s", plugin.Name)
// 		var body []byte
// 		if body, err = httpRequest(l, plugin, url); err != nil {
// 			return nil, err
// 		}
// 		tmpVinfos, err := contentConvertVinfos(string(body), plugin)
// 		if err != nil {
// 			return nil, err
// 		}
// 		vinfos = append(vinfos, tmpVinfos...)
// 	}
// 	return vinfos, nil
// }

// func httpRequest(c *base, content models.WpPackage, url string) (body []byte, err error) {
// 	token := fmt.Sprintf("Token token=%s", c.ServerInfo.WpToken)
// 	var req *http.Request
// 	req, err = http.NewRequest("GET", url, nil)
// 	if err != nil {
// 		return nil, err
// 	}
// 	req.Header.Set("Authorization", token)
// 	client := new(http.Client)
// 	var resp *http.Response
// 	resp, err = client.Do(req)
// 	if err != nil {
// 		return nil, err
// 	}
// 	body, err = ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()
// 	if resp.StatusCode != 200 && resp.StatusCode != 404 {
// 		return nil, fmt.Errorf("status: %s", resp.Status)
// 	} else if resp.StatusCode == 404 {
// 		var jsonError wordpress.WpCveInfos
// 		if err = json.Unmarshal(body, &jsonError); err != nil {
// 			return nil, err
// 		}
// 		if jsonError.Error == "HTTP Token: Access denied.\n" {
// 			return nil, fmt.Errorf("wordpress: HTTP Token: Access denied")
// 		} else if jsonError.Error == "Not found" {
// 			if content.Name == "core" {
// 				return nil, fmt.Errorf("wordpress: core version not found")
// 			}
// 			c.log.Infof("wordpress: %s not found", content.Name)
// 		} else {
// 			return nil, fmt.Errorf("status: %s", resp.Status)
// 		}
// 	}
// 	return body, nil
// }

// func contentConvertVinfos(stdout string, content models.WpPackage) (vinfos []models.VulnInfo, err error) {
// 	data := map[string]wordpress.WpCveInfos{}
// 	if err = json.Unmarshal([]byte(stdout), &data); err != nil {
// 		var jsonError wordpress.WpCveInfos
// 		if err = json.Unmarshal([]byte(stdout), &jsonError); err != nil {
// 			return nil, err
// 		}
// 	}

// 	for _, e := range data {
// 		if len(e.Vulnerabilities) == 0 {
// 			continue
// 		}
// 		for _, vulnerability := range e.Vulnerabilities {
// 			if len(vulnerability.References.Cve) == 0 {
// 				continue
// 			}

// 			var cveIDs []string
// 			for _, cveNumber := range vulnerability.References.Cve {
// 				cveIDs = append(cveIDs, "CVE-"+cveNumber)
// 			}

// 			if len(vulnerability.FixedIn) == 0 {
// 				for _, cveID := range cveIDs {
// 					vinfos = append(vinfos, models.VulnInfo{
// 						CveID: cveID,
// 						CveContents: models.NewCveContents(
// 							models.CveContent{
// 								CveID: cveID,
// 								Title: vulnerability.Title,
// 							},
// 						),
// 						AffectedPackages: models.PackageStatuses{
// 							{
// 								NotFixedYet: true,
// 							},
// 						},
// 					})
// 				}
// 				continue
// 			}
// 			var v1 *version.Version
// 			v1, err = version.NewVersion(content.Version)
// 			if err != nil {
// 				return nil, err
// 			}
// 			var v2 *version.Version
// 			v2, err = version.NewVersion(vulnerability.FixedIn)
// 			if err != nil {
// 				return nil, err
// 			}
// 			if v1.LessThan(v2) {
// 				for _, cveID := range cveIDs {
// 					vinfos = append(vinfos, models.VulnInfo{
// 						CveID: cveID,
// 						CveContents: models.NewCveContents(
// 							models.CveContent{
// 								CveID: cveID,
// 								Title: vulnerability.Title,
// 							},
// 						),
// 						AffectedPackages: models.PackageStatuses{
// 							{
// 								NotFixedYet: false,
// 							},
// 						},
// 					})
// 				}
// 			}
// 		}
// 	}
// 	return vinfos, nil
// }

// func (l *base) wpConvertToModel() models.VulnInfos {
// 	return l.WpVulnInfos
// }
