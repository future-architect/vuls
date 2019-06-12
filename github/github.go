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
	"net/http"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/errof"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
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

	// TODO Use `https://github.com/shurcooL/githubv4` if the tool supports vulnerabilityAlerts Endpoint
	const jsonfmt = `{"query":
	"query { repository(owner:\"%s\", name:\"%s\") { url, vulnerabilityAlerts(first: %d, %s) { pageInfo{ endCursor, hasNextPage, startCursor}, edges { node { id, externalIdentifier, externalReference, fixedIn, packageName,  dismissReason, dismissedAt } } } } }"}`
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

		// https://developer.github.com/v4/previews/#repository-vulnerability-alerts
		// To toggle this preview and access data, need to provide a custom media type in the Accept header:
		// MEMO: I tried to get the affected version via GitHub API. Bit it seems difficult to determin the affected version if there are multiple dependency files such as package.json.
		// TODO remove this header if it is no longer preview status in the future.
		req.Header.Set("Accept", "application/vnd.github.vixen-preview+json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		alerts := SecurityAlerts{}
		if json.NewDecoder(resp.Body).Decode(&alerts); err != nil {
			return 0, err
		}

		util.Log.Debugf("%s", pp.Sprint(alerts))
		if alerts.Data.Repository.URL == "" {
			return 0, errof.New(
				errof.ErrFailedToAccessGithubAPI,
				fmt.Sprintf("Failed to access to GitHub API. Response: %#v", alerts),
			)
		}

		for _, v := range alerts.Data.Repository.VulnerabilityAlerts.Edges {
			if config.Conf.IgnoreGitHubDismissed && v.Node.DismissReason != "" {
				continue
			}

			pkgName := fmt.Sprintf("%s %s",
				alerts.Data.Repository.URL, v.Node.PackageName)

			m := models.GitHubSecurityAlert{
				PackageName:   pkgName,
				FixedIn:       v.Node.FixedIn,
				AffectedRange: v.Node.AffectedRange,
				Dismissed:     len(v.Node.DismissReason) != 0,
				DismissedAt:   v.Node.DismissedAt,
				DismissReason: v.Node.DismissReason,
			}

			cveID := v.Node.ExternalIdentifier

			if val, ok := r.ScannedCves[cveID]; ok {
				val.GitHubSecurityAlerts = val.GitHubSecurityAlerts.Add(m)
				r.ScannedCves[cveID] = val
				nCVEs++
			} else {
				v := models.VulnInfo{
					CveID:                cveID,
					Confidences:          models.Confidences{models.GitHubMatch},
					GitHubSecurityAlerts: models.GitHubSecurityAlerts{m},
				}
				r.ScannedCves[cveID] = v
				nCVEs++
			}
		}
		if !alerts.Data.Repository.VulnerabilityAlerts.PageInfo.HasNextPage {
			break
		}
		after = fmt.Sprintf(`after: \"%s\"`, alerts.Data.Repository.VulnerabilityAlerts.PageInfo.EndCursor)
	}
	return nCVEs, err
}

//SecurityAlerts has detected CVE-IDs, PackageNames, Refs
type SecurityAlerts struct {
	Data struct {
		Repository struct {
			URL                 string `json:"url,omitempty"`
			VulnerabilityAlerts struct {
				PageInfo struct {
					EndCursor   string `json:"endCursor,omitempty"`
					HasNextPage bool   `json:"hasNextPage,omitempty"`
					StartCursor string `json:"startCursor,omitempty"`
				} `json:"pageInfo,omitempty"`
				Edges []struct {
					Node struct {
						ID                 string    `json:"id,omitempty"`
						ExternalIdentifier string    `json:"externalIdentifier,omitempty"`
						ExternalReference  string    `json:"externalReference,omitempty"`
						FixedIn            string    `json:"fixedIn,omitempty"`
						AffectedRange      string    `json:"affectedRange,omitempty"`
						PackageName        string    `json:"packageName,omitempty"`
						DismissReason      string    `json:"dismissReason,omitempty"`
						DismissedAt        time.Time `json:"dismissedAt,omitempty"`
					} `json:"node,omitempty"`
				} `json:"edges,omitempty"`
			} `json:"vulnerabilityAlerts,omitempty"`
		} `json:"repository,omitempty"`
	} `json:"data,omitempty"`
}
