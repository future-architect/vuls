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

	//TODO Pagenation, Use GraphQL Library
	jsonStr := fmt.Sprintf(`{"query":
	"query FindIssueID { repository(owner:\"%s\", name:\"%s\") { name, vulnerabilityAlerts(first: 100) { edges { node { id, externalIdentifier, externalReference, fixedIn, packageName } } } } }"}`, owner, repo)
	req, err := http.NewRequest(
		"POST",
		"https://api.github.com/graphql",
		bytes.NewBuffer([]byte(jsonStr)),
	)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
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
		return
	}

	// TODO add type field to models.Pakcage.
	// OS Packages ... osPkg
	// CPE ... CPE
	// GitHub ... GitHub
	// WordPress theme ... wpTheme
	// WordPress plugin ... wpPlugin
	// WordPress core ... wpCore
	pp.Println(alerts)
	return 0, err
}

//SecurityAlerts has detected CVE-IDs, PackageNames, Refs
type SecurityAlerts struct {
	Data struct {
		Repository struct {
			VulnerabilityAlerts struct {
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
