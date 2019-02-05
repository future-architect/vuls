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

package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
	"golang.org/x/oauth2"
)

// FillGitHubSecurityAlerts access to owner/repo on GitHub and fetch scurity alerts of the repository via GitHub API v4 GraphQL and then set to the given ScanResult.
// https://help.github.com/articles/about-security-alerts-for-vulnerable-dependencies/
func FillGitHubSecurityAlerts(r *models.ScanResult, owner, repo, token string) (nCVEs int, err error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	httpClient := oauth2.NewClient(context.Background(), src)
	const jsonfmt = `{"query":
	"query { repository(owner:\"%s\", name:\"%s\") { name, vulnerabilityAlerts(first: %d, %s) { pageInfo{ endCursor, hasNextPage, startCursor}, edges { node { id, externalIdentifier, externalReference, fixedIn, packageName } } } } }"}`

	after := ""
	for {
		jsonStr := fmt.Sprintf(jsonfmt, owner, repo, 100, after)
		req, err := http.NewRequest("POST",
			"https://api.github.com/graphql",
			bytes.NewBuffer([]byte(jsonStr)),
		)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Content-Type", "application/json")

		// https://developer.github.com/v4/previews/#repository-vulnerability-alerts
		// To toggle this preview and access data, need to provide a custom media type in the Accept header:
		// TODO remove this header if it is no longer preview status in the future.
		req.Header.Set("Accept", "application/vnd.github.vixen-preview+json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return 0, err
		}

		alerts := SecurityAlerts{}
		if err = json.Unmarshal(bodyBytes, &alerts); err != nil {
			return 0, err
		}
		// TODO add type field to models.Pakcage.
		// OS Packages ... osPkg
		// CPE ... CPE
		// GitHub ... GitHub
		// WordPress theme ... wpTheme
		// WordPress plugin ... wpPlugin
		// WordPress core ... wpCore
		pp.Println(alerts)
		if !alerts.Data.Repository.VulnerabilityAlerts.PageInfo.HasNextPage {
			break
		}
		after = fmt.Sprintf(`after: \"%s\"`, alerts.Data.Repository.VulnerabilityAlerts.PageInfo.EndCursor)
	}
	return 0, err
}

//SecurityAlerts has detected CVE-IDs, PackageNames, Refs
type SecurityAlerts struct {
	Data struct {
		Repository struct {
			VulnerabilityAlerts struct {
				PageInfo struct {
					EndCursor   string `json:"endCursor"`
					HasNextPage bool   `json:"hasNextPage"`
					StartCursor string `json:"startCursor"`
				} `json:"pageInfo"`
				Edges []struct {
					Node struct {
						ID                 string `json:"id"`
						ExternalIdentifier string `json:"externalIdentifier"`
						ExternalReference  string `json:"externalReference"`
						FixedIn            string `json:"fixedIn"`
						PackageName        string `json:"packageName"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"vulnerabilityAlerts"`
		} `json:"repository"`
	} `json:"data"`
}
