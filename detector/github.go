//go:build !scanner

package detector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/future-architect/vuls/errof"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"golang.org/x/oauth2"
)

// DetectGitHubSecurityAlerts access to owner/repo on GitHub and fetch security alerts of the repository via GitHub API v4 GraphQL and then set to the given ScanResult.
// https://help.github.com/articles/about-security-alerts-for-vulnerable-dependencies/
func DetectGitHubSecurityAlerts(r *models.ScanResult, owner, repo, token string, ignoreDismissed bool) (nCVEs int, err error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	//TODO Proxy
	httpClient := oauth2.NewClient(context.Background(), src)

	// TODO Use `https://github.com/shurcooL/githubv4` if the tool supports vulnerabilityAlerts Endpoint
	// Memo : https://developer.github.com/v4/explorer/
	const jsonfmt = `{"query":
	"query { repository(owner:\"%s\", name:\"%s\") { url vulnerabilityAlerts(first: %d, states:[OPEN], %s) { pageInfo { endCursor hasNextPage startCursor } edges { node { id dismissReason dismissedAt securityVulnerability{ package { name ecosystem } severity vulnerableVersionRange firstPatchedVersion { identifier } } vulnerableManifestFilename vulnerableManifestPath vulnerableRequirements securityAdvisory { description ghsaId permalink publishedAt summary updatedAt withdrawnAt origin severity references { url } identifiers { type value } } } } } } } "}`
	after := ""

	for {
		jsonStr := fmt.Sprintf(jsonfmt, owner, repo, 100, after)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://api.github.com/graphql",
			bytes.NewBuffer([]byte(jsonStr)),
		)
		defer cancel()
		if err != nil {
			return 0, err
		}

		// https://developer.github.com/v4/previews/#repository-vulnerability-alerts
		// To toggle this preview and access data, need to provide a custom media type in the Accept header:
		// MEMO: I tried to get the affected version via GitHub API. Bit it seems difficult to determine the affected version if there are multiple dependency files such as package.json.
		// TODO remove this header if it is no longer preview status in the future.
		req.Header.Set("Accept", "application/vnd.github.package-deletes-preview+json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return 0, err
		}

		alerts := SecurityAlerts{}
		if err := json.Unmarshal(body, &alerts); err != nil {
			return 0, err
		}

		// util.Log.Debugf("%s", pp.Sprint(alerts))
		// util.Log.Debugf("%s", string(body))
		if alerts.Data.Repository.URL == "" {
			return 0, errof.New(errof.ErrFailedToAccessGithubAPI,
				fmt.Sprintf("Failed to access to GitHub API. Response: %s", string(body)))
		}

		for _, v := range alerts.Data.Repository.VulnerabilityAlerts.Edges {
			if ignoreDismissed && v.Node.DismissReason != "" {
				continue
			}

			m := models.GitHubSecurityAlert{
				Repository: alerts.Data.Repository.URL,
				Package: models.GSAVulnerablePackage{
					Name:             v.Node.SecurityVulnerability.Package.Name,
					Ecosystem:        v.Node.SecurityVulnerability.Package.Ecosystem,
					ManifestFilename: v.Node.VulnerableManifestFilename,
					ManifestPath:     v.Node.VulnerableManifestPath,
					Requirements:     v.Node.VulnerableRequirements,
				},
				FixedIn:       v.Node.SecurityVulnerability.FirstPatchedVersion.Identifier,
				AffectedRange: v.Node.SecurityVulnerability.VulnerableVersionRange,
				Dismissed:     len(v.Node.DismissReason) != 0,
				DismissedAt:   v.Node.DismissedAt,
				DismissReason: v.Node.DismissReason,
			}

			cveIDs, other := []string{}, []string{}
			for _, identifier := range v.Node.SecurityAdvisory.Identifiers {
				if identifier.Type == "CVE" {
					cveIDs = append(cveIDs, identifier.Value)
				} else {
					other = append(other, identifier.Value)
				}
			}

			// If CVE-ID has not been assigned, use the GHSA ID etc as a ID.
			if len(cveIDs) == 0 {
				cveIDs = other
			}

			refs := []models.Reference{}
			for _, r := range v.Node.SecurityAdvisory.References {
				refs = append(refs, models.Reference{Link: r.URL})
			}

			for _, cveID := range cveIDs {
				cveContent := models.CveContent{
					Type:          models.GitHub,
					CveID:         cveID,
					Title:         v.Node.SecurityAdvisory.Summary,
					Summary:       v.Node.SecurityAdvisory.Description,
					Cvss2Severity: v.Node.SecurityVulnerability.Severity,
					Cvss3Severity: v.Node.SecurityVulnerability.Severity,
					SourceLink:    v.Node.SecurityAdvisory.Permalink,
					References:    refs,
					Published:     v.Node.SecurityAdvisory.PublishedAt,
					LastModified:  v.Node.SecurityAdvisory.UpdatedAt,
				}

				if val, ok := r.ScannedCves[cveID]; ok {
					val.GitHubSecurityAlerts = val.GitHubSecurityAlerts.Add(m)
					val.CveContents[models.GitHub] = []models.CveContent{cveContent}
					r.ScannedCves[cveID] = val
				} else {
					v := models.VulnInfo{
						CveID:                cveID,
						Confidences:          models.Confidences{models.GitHubMatch},
						GitHubSecurityAlerts: models.GitHubSecurityAlerts{m},
						CveContents:          models.NewCveContents(cveContent),
					}
					r.ScannedCves[cveID] = v
				}
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

// SecurityAlerts has detected CVE-IDs, PackageNames, Refs
type SecurityAlerts struct {
	Data struct {
		Repository struct {
			URL                 string `json:"url"`
			VulnerabilityAlerts struct {
				PageInfo struct {
					EndCursor   string `json:"endCursor"`
					HasNextPage bool   `json:"hasNextPage"`
					StartCursor string `json:"startCursor"`
				} `json:"pageInfo"`
				Edges []struct {
					Node struct {
						ID                    string    `json:"id"`
						DismissReason         string    `json:"dismissReason"`
						DismissedAt           time.Time `json:"dismissedAt"`
						SecurityVulnerability struct {
							Package struct {
								Name      string `json:"name"`
								Ecosystem string `json:"ecosystem"`
							} `json:"package"`
							Severity               string `json:"severity"`
							VulnerableVersionRange string `json:"vulnerableVersionRange"`
							FirstPatchedVersion    struct {
								Identifier string `json:"identifier"`
							} `json:"firstPatchedVersion"`
						} `json:"securityVulnerability"`
						VulnerableManifestFilename string `json:"vulnerableManifestFilename"`
						VulnerableManifestPath     string `json:"vulnerableManifestPath"`
						VulnerableRequirements     string `json:"vulnerableRequirements"`
						SecurityAdvisory           struct {
							Description string    `json:"description"`
							GhsaID      string    `json:"ghsaId"`
							Permalink   string    `json:"permalink"`
							PublishedAt time.Time `json:"publishedAt"`
							Summary     string    `json:"summary"`
							UpdatedAt   time.Time `json:"updatedAt"`
							WithdrawnAt time.Time `json:"withdrawnAt"`
							Origin      string    `json:"origin"`
							Severity    string    `json:"severity"`
							References  []struct {
								URL string `json:"url"`
							} `json:"references"`
							Identifiers []struct {
								Type  string `json:"type"`
								Value string `json:"value"`
							} `json:"identifiers"`
						} `json:"securityAdvisory"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"vulnerabilityAlerts"`
		} `json:"repository"`
	} `json:"data"`
}

// DetectGitHubDependencyGraph access to owner/repo on GitHub and fetch dependency graph of the repository via GitHub API v4 GraphQL and then set to the given ScanResult.
// https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph
func DetectGitHubDependencyGraph(r *models.ScanResult, owner, repo, token string) (err error) {
	src := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	//TODO Proxy
	httpClient := oauth2.NewClient(context.Background(), src)

	return fetchDependencyGraph(r, httpClient, owner, repo, "", "", 10, 100)
}

// recursive function
func fetchDependencyGraph(r *models.ScanResult, httpClient *http.Client, owner, repo, after, dependenciesAfter string, first, dependenciesFirst int) (err error) {
	const queryFmt = `{"query":
	"query { repository(owner:\"%s\", name:\"%s\") { url dependencyGraphManifests(first: %d, withDependencies: true%s) { pageInfo { endCursor hasNextPage } edges { node { blobPath filename repository { url } parseable exceedsMaxSize dependenciesCount dependencies(first: %d%s) { pageInfo { endCursor hasNextPage } edges { node { packageName packageManager repository { url } requirements hasDependencies } } } } } } } }"}`
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var graph DependencyGraph
	rateLimitRemaining := 5000
	count, retryMax := 0, 10
	retryCheck := func(err error) error {
		if count == retryMax {
			return backoff.Permanent(err)
		}
		if rateLimitRemaining == 0 {
			// The GraphQL API rate limit is 5,000 points per hour.
			// Terminate　with an error on rate limit reached.
			return backoff.Permanent(errof.New(errof.ErrFailedToAccessGithubAPI,
				fmt.Sprintf("rate limit exceeded. error: %s", err.Error())))
		}
		return err
	}
	operation := func() error {
		count++
		queryStr := fmt.Sprintf(queryFmt, owner, repo, first, after, dependenciesFirst, dependenciesAfter)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			"https://api.github.com/graphql",
			bytes.NewBuffer([]byte(queryStr)),
		)
		if err != nil {
			return retryCheck(err)
		}

		// https://docs.github.com/en/graphql/overview/schema-previews#access-to-a-repository-s-dependency-graph-preview
		// TODO remove this header if it is no longer preview status in the future.
		req.Header.Set("Accept", "application/vnd.github.hawkgirl-preview+json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := httpClient.Do(req)
		if err != nil {
			return retryCheck(err)
		}
		defer resp.Body.Close()

		// https://docs.github.com/en/graphql/overview/resource-limitations#rate-limit
		if rateLimitRemaining, err = strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining")); err != nil {
			// If the header retrieval fails, rateLimitRemaining will be set to 0,
			// preventing further retries. To enable retry, we reset it to 5000.
			rateLimitRemaining = 5000
			return retryCheck(errof.New(errof.ErrFailedToAccessGithubAPI, "Failed to get X-RateLimit-Remaining header"))
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return retryCheck(err)
		}

		graph = DependencyGraph{}
		if err := json.Unmarshal(body, &graph); err != nil {
			return retryCheck(err)
		}

		if len(graph.Errors) > 0 || graph.Data.Repository.URL == "" {
			// this mainly occurs on timeout
			// reduce the number of dependencies to be fetched for the next retry
			if dependenciesFirst > 50 {
				dependenciesFirst -= 5
			}
			return retryCheck(errof.New(errof.ErrFailedToAccessGithubAPI,
				fmt.Sprintf("Failed to access to GitHub API. Repository: %s/%s; Response: %s", owner, repo, string(body))))
		}

		return nil
	}
	notify := func(err error, t time.Duration) {
		logging.Log.Warnf("Failed attempts (count: %d). retrying in %s. err: %+v", count, t, err)
	}

	if err = backoff.RetryNotify(operation, backoff.NewExponentialBackOff(), notify); err != nil {
		return err
	}

	dependenciesAfter = ""
	for _, m := range graph.Data.Repository.DependencyGraphManifests.Edges {
		manifest, ok := r.GitHubManifests[m.Node.BlobPath]
		if !ok {
			manifest = models.DependencyGraphManifest{
				BlobPath:     m.Node.BlobPath,
				Filename:     m.Node.Filename,
				Repository:   m.Node.Repository.URL,
				Dependencies: []models.Dependency{},
			}
		}
		for _, d := range m.Node.Dependencies.Edges {
			manifest.Dependencies = append(manifest.Dependencies, models.Dependency{
				PackageName:    d.Node.PackageName,
				PackageManager: d.Node.PackageManager,
				Repository:     d.Node.Repository.URL,
				Requirements:   d.Node.Requirements,
			})
		}
		r.GitHubManifests[m.Node.BlobPath] = manifest

		if m.Node.Dependencies.PageInfo.HasNextPage {
			dependenciesAfter = fmt.Sprintf(`, after: \"%s\"`, m.Node.Dependencies.PageInfo.EndCursor)
		}
	}
	if dependenciesAfter != "" {
		return fetchDependencyGraph(r, httpClient, owner, repo, after, dependenciesAfter, first, dependenciesFirst)
	}

	if graph.Data.Repository.DependencyGraphManifests.PageInfo.HasNextPage {
		after = fmt.Sprintf(`, after: \"%s\"`, graph.Data.Repository.DependencyGraphManifests.PageInfo.EndCursor)
		return fetchDependencyGraph(r, httpClient, owner, repo, after, dependenciesAfter, first, dependenciesFirst)
	}

	return nil
}

// DependencyGraph is a GitHub API response
type DependencyGraph struct {
	Data struct {
		Repository struct {
			URL                      string `json:"url"`
			DependencyGraphManifests struct {
				PageInfo struct {
					EndCursor   string `json:"endCursor"`
					HasNextPage bool   `json:"hasNextPage"`
				} `json:"pageInfo"`
				Edges []struct {
					Node struct {
						BlobPath   string `json:"blobPath"`
						Filename   string `json:"filename"`
						Repository struct {
							URL string `json:"url"`
						}
						Parseable         bool `json:"parseable"`
						ExceedsMaxSize    bool `json:"exceedsMaxSize"`
						DependenciesCount int  `json:"dependenciesCount"`
						Dependencies      struct {
							PageInfo struct {
								EndCursor   string `json:"endCursor"`
								HasNextPage bool   `json:"hasNextPage"`
							} `json:"pageInfo"`
							Edges []struct {
								Node struct {
									PackageName    string `json:"packageName"`
									PackageManager string `json:"packageManager"`
									Repository     struct {
										URL string `json:"url"`
									}
									Requirements    string `json:"requirements"`
									HasDependencies bool   `json:"hasDependencies"`
								} `json:"node"`
							} `json:"edges"`
						} `json:"dependencies"`
					} `json:"node"`
				} `json:"edges"`
			} `json:"dependencyGraphManifests"`
		} `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Type      string `json:"type,omitempty"`
		Path      []any  `json:"path,omitempty"`
		Locations []struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"locations,omitempty"`
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}
