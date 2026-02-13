package models

import (
	"bytes"
	"cmp"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/future-architect/vuls/logging"
	exploitmodels "github.com/vulsio/go-exploitdb/models"
)

// VulnInfos has a map of VulnInfo
// Key: CveID
type VulnInfos map[string]VulnInfo

// Find elements that matches the function passed in argument
func (v VulnInfos) Find(f func(VulnInfo) bool) VulnInfos {
	filtered := VulnInfos{}
	for _, vv := range v {
		if f(vv) {
			filtered[vv.CveID] = vv
		}
	}
	return filtered
}

// FilterByCvssOver return scored vulnerabilities
func (v VulnInfos) FilterByCvssOver(over float64) (_ VulnInfos, nFiltered int) {
	return v.Find(func(v VulnInfo) bool {
		if over <= v.MaxCvssScore().Value.Score {
			return true
		}
		nFiltered++
		return false
	}), nFiltered
}

// FilterByConfidenceOver scored vulnerabilities
func (v VulnInfos) FilterByConfidenceOver(over int) (_ VulnInfos, nFiltered int) {
	return v.Find(func(v VulnInfo) bool {
		for _, c := range v.Confidences {
			if over <= c.Score {
				return true
			}
		}
		nFiltered++
		return false
	}), nFiltered
}

// FilterIgnoreCves filter function.
func (v VulnInfos) FilterIgnoreCves(ignoreCveIDs []string) (_ VulnInfos, nFiltered int) {
	return v.Find(func(v VulnInfo) bool {
		if slices.Contains(ignoreCveIDs, v.CveID) {
			nFiltered++
			return false
		}
		return true
	}), nFiltered
}

// FilterUnfixed filter unfixed CVE-IDs
func (v VulnInfos) FilterUnfixed(ignoreUnfixed bool) (_ VulnInfos, nFiltered int) {
	if !ignoreUnfixed {
		return v, 0
	}
	return v.Find(func(v VulnInfo) bool {
		// Report cves detected by CPE because Vuls can't know 'fixed' or 'unfixed'
		if len(v.CpeURIs) != 0 {
			return true
		}
		NotFixedAll := true
		for _, p := range v.AffectedPackages {
			NotFixedAll = NotFixedAll && p.NotFixedYet
		}
		if NotFixedAll {
			nFiltered++
		}
		return !NotFixedAll
	}), nFiltered
}

// FilterIgnorePkgs is filter function.
func (v VulnInfos) FilterIgnorePkgs(ignorePkgsRegexps []string) (_ VulnInfos, nFiltered int) {
	regexps := []*regexp.Regexp{}
	for _, pkgRegexp := range ignorePkgsRegexps {
		re, err := regexp.Compile(pkgRegexp)
		if err != nil {
			logging.Log.Warnf("Failed to parse %s. err: %+v", pkgRegexp, err)
			continue
		}
		regexps = append(regexps, re)
	}
	if len(regexps) == 0 {
		return v, 0
	}

	return v.Find(func(v VulnInfo) bool {
		if len(v.AffectedPackages) == 0 {
			return true
		}
		for _, p := range v.AffectedPackages {
			match := false
			for _, re := range regexps {
				if re.MatchString(p.Name) {
					match = true
				}
			}
			if !match {
				return true
			}
		}
		nFiltered++
		return false
	}), nFiltered
}

// FindScoredVulns return scored vulnerabilities
func (v VulnInfos) FindScoredVulns() (_ VulnInfos, nFiltered int) {
	return v.Find(func(vv VulnInfo) bool {
		if 0 < vv.MaxCvss2Score().Value.Score || 0 < vv.MaxCvss3Score().Value.Score || 0 < vv.MaxCvss40Score().Value.Score {
			return true
		}
		nFiltered++
		return false
	}), nFiltered
}

// ToSortedSlice returns slice of VulnInfos that is sorted by Score, CVE-ID
func (v VulnInfos) ToSortedSlice() (sorted []VulnInfo) {
	sorted = slices.Collect(maps.Values(v))
	slices.SortFunc(sorted, func(a, b VulnInfo) int {
		maxA := a.MaxCvssScore()
		maxB := b.MaxCvssScore()
		return cmp.Or(
			-cmp.Compare(maxA.Value.Score, maxB.Value.Score),
			cmp.Compare(a.CveID, b.CveID),
		)
	})
	return
}

// CountGroupBySeverity summarize the number of CVEs group by CVSSv2 Severity
func (v VulnInfos) CountGroupBySeverity() map[string]int {
	m := map[string]int{}
	for _, vInfo := range v {
		score := vInfo.MaxCvss40Score().Value.Score
		if score < 0.1 {
			score = vInfo.MaxCvss3Score().Value.Score
		}
		if score < 0.1 {
			score = vInfo.MaxCvss2Score().Value.Score
		}
		switch {
		case 9 <= score:
			m["Critical"]++
		case 7.0 <= score:
			m["High"]++
		case 4.0 <= score:
			m["Medium"]++
		case 0 < score:
			m["Low"]++
		default:
			m["Unknown"]++
		}
	}
	return m
}

// FormatCveSummary summarize the number of CVEs group by CVSSv2 Severity
func (v VulnInfos) FormatCveSummary() string {
	m := v.CountGroupBySeverity()
	line := fmt.Sprintf("Total: %d (Critical:%d High:%d Medium:%d Low:%d ?:%d)",
		m["Critical"]+m["High"]+m["Medium"]+m["Low"]+m["Unknown"],
		m["Critical"], m["High"], m["Medium"], m["Low"], m["Unknown"])

	nPlus, nMinus := v.CountDiff()
	if 0 < nPlus || 0 < nMinus {
		line = fmt.Sprintf("%s +%d -%d", line, nPlus, nMinus)
	}
	return line
}

// FormatFixedStatus summarize the number of cves are fixed.
func (v VulnInfos) FormatFixedStatus(packs Packages) string {
	total, fixed := 0, 0
	for _, vInfo := range v {
		if len(vInfo.CpeURIs) != 0 {
			continue
		}
		total++
		if vInfo.PatchStatus(packs) == "fixed" {
			fixed++
		}
	}
	return fmt.Sprintf("%d/%d Fixed", fixed, total)
}

// CountDiff counts the number of added/removed CVE-ID
func (v VulnInfos) CountDiff() (nPlus int, nMinus int) {
	for _, vInfo := range v {
		switch vInfo.DiffStatus {
		case DiffPlus:
			nPlus++
		case DiffMinus:
			nMinus++
		default:
		}
	}
	return
}

// PackageFixStatuses is a list of PackageStatus
type PackageFixStatuses []PackageFixStatus

// Names return a slice of package names
func (ps PackageFixStatuses) Names() (names []string) {
	for _, p := range ps {
		names = append(names, p.Name)
	}
	return names
}

// Store insert given pkg if missing, update pkg if exists
func (ps PackageFixStatuses) Store(pkg PackageFixStatus) PackageFixStatuses {
	for i, p := range ps {
		if p.Name == pkg.Name {
			ps[i] = pkg
			return ps
		}
	}
	ps = append(ps, pkg)
	return ps
}

// Sort by Name asc, FixedIn desc
func (ps PackageFixStatuses) Sort() {
	slices.SortFunc(ps, func(a, b PackageFixStatus) int {
		return cmp.Or(
			cmp.Compare(a.Name, b.Name),
			cmp.Compare(b.FixedIn, a.FixedIn),
		)
	})
}

// PackageFixStatus has name and other status about the package
type PackageFixStatus struct {
	Name        string `json:"name,omitempty"`
	NotFixedYet bool   `json:"notFixedYet,omitempty"`
	FixState    string `json:"fixState,omitempty"`
	FixedIn     string `json:"fixedIn,omitempty"`
}

// VulnInfo has a vulnerability information and unsecure packages
type VulnInfo struct {
	CveID                string               `json:"cveID,omitempty"`
	Confidences          Confidences          `json:"confidences,omitempty"`
	AffectedPackages     PackageFixStatuses   `json:"affectedPackages,omitempty"`
	DistroAdvisories     DistroAdvisories     `json:"distroAdvisories,omitempty"` // for Amazon, RHEL, Fedora, FreeBSD, Microsoft
	CveContents          CveContents          `json:"cveContents,omitempty"`
	Exploits             []Exploit            `json:"exploits,omitempty"`
	Metasploits          []Metasploit         `json:"metasploits,omitempty"`
	Mitigations          []Mitigation         `json:"mitigations,omitempty"`
	KEVs                 []KEV                `json:"kevs,omitempty"`
	Ctis                 []string             `json:"ctis,omitempty"`
	AlertDict            AlertDict            `json:"alertDict,omitzero"`
	CpeURIs              []string             `json:"cpeURIs,omitempty"` // CpeURIs related to this CVE defined in config.toml
	GitHubSecurityAlerts GitHubSecurityAlerts `json:"gitHubSecurityAlerts,omitempty"`
	WpPackageFixStats    WpPackageFixStats    `json:"wpPackageFixStats,omitempty"`
	LibraryFixedIns      LibraryFixedIns      `json:"libraryFixedIns,omitempty"`
	WindowsKBFixedIns    []string             `json:"windowsKBFixedIns,omitempty"`
	VulnType             string               `json:"vulnType,omitempty"`
	DiffStatus           DiffStatus           `json:"diffStatus,omitempty"`
}

// Alert has CERT alert information
type Alert struct {
	URL   string `json:"url,omitempty"`
	Title string `json:"title,omitempty"`
	Team  string `json:"team,omitempty"`
}

// GitHubSecurityAlerts is a list of GitHubSecurityAlert
type GitHubSecurityAlerts []GitHubSecurityAlert

// Add adds given arg to the slice and return the slice (immutable)
func (g GitHubSecurityAlerts) Add(alert GitHubSecurityAlert) GitHubSecurityAlerts {
	for _, a := range g {
		if a.RepoURLPackageName() == alert.RepoURLPackageName() {
			return g
		}
	}
	return append(g, alert)
}

// Names return a slice of lib names
func (g GitHubSecurityAlerts) Names() (names []string) {
	for _, a := range g {
		names = append(names, a.RepoURLPackageName())
	}
	return names
}

// GitHubSecurityAlert has detected CVE-ID, GSAVulnerablePackage, Status fetched via GitHub API
type GitHubSecurityAlert struct {
	Repository    string               `json:"repository"`
	Package       GSAVulnerablePackage `json:"package,omitzero"`
	FixedIn       string               `json:"fixedIn"`
	AffectedRange string               `json:"affectedRange"`
	Dismissed     bool                 `json:"dismissed"`
	DismissedAt   time.Time            `json:"dismissedAt"`
	DismissReason string               `json:"dismissReason"`
}

// RepoURLPackageName returns a string connecting the repository and package name
func (a GitHubSecurityAlert) RepoURLPackageName() string {
	return fmt.Sprintf("%s %s", a.Repository, a.Package.Name)
}

// RepoURLManifestPath should be same format with DependencyGraphManifest.RepoURLFilename()
func (a GitHubSecurityAlert) RepoURLManifestPath() string {
	return fmt.Sprintf("%s/%s", a.Repository, a.Package.ManifestPath)
}

// GSAVulnerablePackage has vulnerable package information
type GSAVulnerablePackage struct {
	Name             string `json:"name"`
	Ecosystem        string `json:"ecosystem"`
	ManifestFilename string `json:"manifestFilename"`
	ManifestPath     string `json:"manifestPath"`
	Requirements     string `json:"requirements"`
}

// LibraryFixedIns is a list of Library's FixedIn
type LibraryFixedIns []LibraryFixedIn

// Names return a slice of names
func (lfs LibraryFixedIns) Names() (names []string) {
	for _, lf := range lfs {
		names = append(names, lf.Name)
	}
	return names
}

// WpPackageFixStats is a list of WpPackageFixStatus
type WpPackageFixStats []WpPackageFixStatus

// Names return a slice of names
func (ws WpPackageFixStats) Names() (names []string) {
	for _, w := range ws {
		names = append(names, w.Name)
	}
	return names
}

// WpPackages has a list of WpPackage
type WpPackages []WpPackage

// Add adds given arg to the slice and return the slice (immutable)
func (g WpPackages) Add(pkg WpPackage) WpPackages {
	for _, a := range g {
		if a.Name == pkg.Name {
			return g
		}
	}
	return append(g, pkg)
}

// DiffStatus keeps a comparison with the previous detection results for this CVE
type DiffStatus string

const (
	// DiffPlus is newly detected CVE
	DiffPlus = DiffStatus("+")

	// DiffMinus is resolved CVE
	DiffMinus = DiffStatus("-")
)

// CveIDDiffFormat format CVE-ID for diff mode
func (v VulnInfo) CveIDDiffFormat() string {
	if v.DiffStatus != "" {
		return fmt.Sprintf("%s %s", v.DiffStatus, v.CveID)
	}
	return v.CveID
}

// Titles returns title (TUI)
func (v VulnInfo) Titles(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if conts, found := v.CveContents[Jvn]; found {
			for _, cont := range conts {
				if cont.Title != "" {
					values = append(values, CveContentStr{Jvn, cont.Title})
				}
			}
		}
	}

	// RedHat API has one line title.
	if conts, found := v.CveContents[RedHatAPI]; found {
		for _, cont := range conts {
			if cont.Title != "" {
				values = append(values, CveContentStr{RedHatAPI, cont.Title})
			}
		}
	}

	// GitHub security alerts has a title.
	if conts, found := v.CveContents[GitHub]; found {
		for _, cont := range conts {
			if cont.Title != "" {
				values = append(values, CveContentStr{GitHub, cont.Title})
			}
		}
	}

	order := append(GetCveContentTypes(string(Trivy)), append(CveContentTypes{Cisco, Paloalto, Fortinet, Euvd, Nvd, Vulncheck, Mitre}, GetCveContentTypes(myFamily)...)...)
	order = append(order, AllCveContetTypes.Except(append(order, Jvn)...)...)
	for _, ctype := range order {
		if conts, found := v.CveContents[ctype]; found {
			for _, cont := range conts {
				if cont.Summary != "" {
					values = append(values, CveContentStr{
						Type:  ctype,
						Value: strings.ReplaceAll(cont.Summary, "\n", " "),
					})
				}
			}
		}
	}

	for _, adv := range v.DistroAdvisories {
		values = append(values, CveContentStr{
			Type:  "Vendor",
			Value: strings.ReplaceAll(adv.Description, "\n", " "),
		})
	}

	if len(values) == 0 {
		values = []CveContentStr{{
			Type:  Unknown,
			Value: "-",
		}}
	}
	return
}

// Summaries returns summaries
func (v VulnInfo) Summaries(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if conts, found := v.CveContents[Jvn]; found {
			for _, cont := range conts {
				if cont.Summary != "" {
					summary := cont.Title
					summary += "\n" + strings.ReplaceAll(strings.ReplaceAll(cont.Summary, "\n", " "), "\r", " ")
					values = append(values, CveContentStr{Jvn, summary})
				}
			}
		}
	}

	order := append(append(GetCveContentTypes(string(Trivy)), GetCveContentTypes(myFamily)...), Cisco, Paloalto, Fortinet, Euvd, Nvd, Vulncheck, Mitre, GitHub)
	order = append(order, AllCveContetTypes.Except(append(order, Jvn)...)...)
	for _, ctype := range order {
		if conts, found := v.CveContents[ctype]; found {
			for _, cont := range conts {
				if cont.Summary != "" {
					summary := strings.ReplaceAll(cont.Summary, "\n", " ")
					values = append(values, CveContentStr{
						Type:  ctype,
						Value: summary,
					})
				}
			}
		}
	}

	for _, adv := range v.DistroAdvisories {
		values = append(values, CveContentStr{
			Type:  "Vendor",
			Value: adv.Description,
		})
	}

	if conts, ok := v.CveContents[WpScan]; ok {
		for _, cont := range conts {
			if cont.Title != "" {
				values = append(values, CveContentStr{
					Type:  WpScan,
					Value: cont.Title,
				})
			}
		}
	}

	if len(values) == 0 {
		return []CveContentStr{{
			Type:  Unknown,
			Value: "-",
		}}
	}

	return
}

// Cvss2Scores returns CVSS V2 Scores
func (v VulnInfo) Cvss2Scores() (values []CveContentCvss) {
	order := append([]CveContentType{RedHatAPI, RedHat, Nvd, Vulncheck, Mitre, Jvn, Euvd}, GetCveContentTypes(string(Trivy))...)
	for _, ctype := range order {
		if conts, found := v.CveContents[ctype]; found {
			for _, cont := range conts {
				if cont.Cvss2Score == 0 && cont.Cvss2Severity == "" {
					continue
				}
				// https://nvd.nist.gov/vuln-metrics/cvss
				values = append(values, CveContentCvss{
					Type: ctype,
					Value: Cvss{
						Type:     CVSS2,
						Score:    cont.Cvss2Score,
						Vector:   cont.Cvss2Vector,
						Severity: strings.ToUpper(cont.Cvss2Severity),
					},
				})
			}
		}
	}
	return
}

// Cvss3Scores returns CVSS V3 Score
func (v VulnInfo) Cvss3Scores() (values []CveContentCvss) {
	order := append([]CveContentType{RedHatAPI, RedHat, Rocky, SUSE, Microsoft, Paloalto, Fortinet, Nvd, Vulncheck, Mitre, Jvn, Euvd}, GetCveContentTypes(string(Trivy))...)
	for _, ctype := range order {
		if conts, found := v.CveContents[ctype]; found {
			for _, cont := range conts {
				if cont.Cvss3Score == 0 && cont.Cvss3Severity == "" {
					continue
				}
				// https://nvd.nist.gov/vuln-metrics/cvss
				values = append(values, CveContentCvss{
					Type: ctype,
					Value: Cvss{
						Type:     CVSS3,
						Score:    cont.Cvss3Score,
						Vector:   cont.Cvss3Vector,
						Severity: strings.ToUpper(cont.Cvss3Severity),
					},
				})
			}
		}
	}

	for _, ctype := range append([]CveContentType{Debian, DebianSecurityTracker, Ubuntu, UbuntuAPI, Amazon, GitHub, WpScan}, GetCveContentTypes(string(Trivy))...) {
		if conts, found := v.CveContents[ctype]; found {
			for _, cont := range conts {
				if cont.Cvss3Severity != "" {
					switch ctype {
					case DebianSecurityTracker: // Multiple Severities(sorted) may be listed, and the largest one is used.
						ss := strings.Split(cont.Cvss3Severity, "|")
						values = append(values, CveContentCvss{
							Type: ctype,
							Value: Cvss{
								Type:                 CVSS3,
								Score:                severityToCvssScoreRoughly(ss[len(ss)-1]),
								CalculatedBySeverity: true,
								Severity:             strings.ToUpper(cont.Cvss3Severity),
							},
						})
					default:
						values = append(values, CveContentCvss{
							Type: ctype,
							Value: Cvss{
								Type:                 CVSS3,
								Score:                severityToCvssScoreRoughly(cont.Cvss3Severity),
								CalculatedBySeverity: true,
								Severity:             strings.ToUpper(cont.Cvss3Severity),
							},
						})
					}
				}
			}
		}
	}

	// Memo: Only RedHat, SUSE, Oracle and Amazon has severity data in advisory.
	for _, adv := range v.DistroAdvisories {
		if adv.Severity != "" {
			score := severityToCvssScoreRoughly(adv.Severity)
			values = append(values, CveContentCvss{
				Type: "Vendor",
				Value: Cvss{
					Type:                 CVSS3,
					Score:                score,
					CalculatedBySeverity: true,
					Severity:             strings.ToUpper(adv.Severity),
				},
			})
		}
	}
	return
}

// Cvss40Scores returns CVSS V4 Score
func (v VulnInfo) Cvss40Scores() (values []CveContentCvss) {
	for _, ctype := range []CveContentType{Paloalto, Mitre, Nvd, Vulncheck, Euvd} {
		if conts, found := v.CveContents[ctype]; found {
			for _, cont := range conts {
				if cont.Cvss40Score == 0 && cont.Cvss40Severity == "" {
					continue
				}
				// https://nvd.nist.gov/vuln-metrics/cvss
				values = append(values, CveContentCvss{
					Type: ctype,
					Value: Cvss{
						Type:     CVSS40,
						Score:    cont.Cvss40Score,
						Vector:   cont.Cvss40Vector,
						Severity: strings.ToUpper(cont.Cvss40Severity),
					},
				})
			}
		}
	}
	return
}

// MaxCvssScore returns max CVSS Score
// If there is no CVSS Score, return Severity as a numerical value.
func (v VulnInfo) MaxCvssScore() CveContentCvss {
	v40Max := v.MaxCvss40Score()
	if v40Max.Type != Unknown {
		return v40Max
	}
	v3Max := v.MaxCvss3Score()
	if v3Max.Type != Unknown {
		return v3Max
	}
	return v.MaxCvss2Score()
}

// MaxCvss40Score returns Max CVSS V4.0 Score
func (v VulnInfo) MaxCvss40Score() CveContentCvss {
	maxCvss := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS40},
	}
	for _, cvss := range v.Cvss40Scores() {
		if maxCvss.Value.Score < cvss.Value.Score {
			maxCvss = cvss
		}
	}
	return maxCvss
}

// MaxCvss3Score returns Max CVSS V3 Score
func (v VulnInfo) MaxCvss3Score() CveContentCvss {
	maxCvss := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS3},
	}
	for _, cvss := range v.Cvss3Scores() {
		if maxCvss.Value.Score < cvss.Value.Score {
			maxCvss = cvss
		}
	}
	return maxCvss
}

// MaxCvss2Score returns Max CVSS V2 Score
func (v VulnInfo) MaxCvss2Score() CveContentCvss {
	maxCvss := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS2},
	}
	for _, cvss := range v.Cvss2Scores() {
		if maxCvss.Value.Score < cvss.Value.Score {
			maxCvss = cvss
		}
	}
	return maxCvss
}

// AttackVector returns attack vector string
func (v VulnInfo) AttackVector() string {
	for _, conts := range v.CveContents {
		for _, cont := range conts {
			switch {
			case strings.HasPrefix(cont.Cvss2Vector, "AV:N") || strings.Contains(cont.Cvss3Vector, "AV:N") || strings.Contains(cont.Cvss40Vector, "AV:N"):
				return "AV:N"
			case strings.HasPrefix(cont.Cvss2Vector, "AV:A") || strings.Contains(cont.Cvss3Vector, "AV:A") || strings.Contains(cont.Cvss40Vector, "AV:A"):
				return "AV:A"
			case strings.HasPrefix(cont.Cvss2Vector, "AV:L") || strings.Contains(cont.Cvss3Vector, "AV:L") || strings.Contains(cont.Cvss40Vector, "AV:L"):
				return "AV:L"
			case strings.Contains(cont.Cvss3Vector, "AV:P") || strings.Contains(cont.Cvss40Vector, "AV:P"): // no AV:P in CVSS v2
				return "AV:P"
			}
		}
	}
	if conts, found := v.CveContents[DebianSecurityTracker]; found {
		for _, cont := range conts {
			if attackRange, found := cont.Optional["attack range"]; found {
				return attackRange
			}
		}
	}
	return ""
}

// PatchStatus returns fixed or unfixed string
func (v VulnInfo) PatchStatus(packs Packages) string {
	if slices.Contains(v.Confidences, WindowsRoughMatch) {
		return "unknown"
	}

	if slices.Contains(v.Confidences, WindowsUpdateSearch) {
		if slices.ContainsFunc(v.AffectedPackages, func(e PackageFixStatus) bool { return e.FixState == "unknown" }) {
			return "unknown"
		}
		if slices.ContainsFunc(v.AffectedPackages, func(e PackageFixStatus) bool { return e.FixState == "unfixed" }) || (len(v.AffectedPackages) == 0 && len(v.WindowsKBFixedIns) == 0) {
			return "unfixed"
		}
		return "fixed"
	}

	// Vuls don't know patch status of the CPE
	if len(v.CpeURIs) > 0 {
		return ""
	}

	for _, p := range v.AffectedPackages {
		if p.NotFixedYet {
			return "unfixed"
		}

		// Fast and offline mode can not get the candidate version.
		// Vuls can be considered as 'fixed' if not-fixed-yet==true and
		// the fixed-in-version (information in the oval) is not an empty.
		if p.FixedIn != "" {
			continue
		}

		// fast, offline mode doesn't have new version
		if pack, ok := packs[p.Name]; ok {
			if pack.NewVersion == "" {
				return "unknown"
			}
		}
	}

	return "fixed"
}

// CveContentCvss has CVSS information
type CveContentCvss struct {
	Type  CveContentType `json:"type"`
	Value Cvss           `json:"value"`
}

// CvssType Represent the type of CVSS
type CvssType string

const (
	// CVSS2 means CVSS version2
	CVSS2 CvssType = "2"

	// CVSS3 means CVSS version3
	CVSS3 CvssType = "3"

	// CVSS40 means CVSS version4.0
	CVSS40 CvssType = "4.0"
)

// Cvss has CVSS Score
type Cvss struct {
	Type                 CvssType `json:"type"`
	Score                float64  `json:"score"`
	CalculatedBySeverity bool     `json:"calculatedBySeverity"`
	Vector               string   `json:"vector"`
	Severity             string   `json:"severity"`
}

// Format CVSS Score and Vector
func (c Cvss) Format() string {
	if c.Vector == "" {
		return fmt.Sprintf("%s %s", c.SeverityToCvssScoreRange(), c.Severity)
	}
	return fmt.Sprintf("%3.1f/%s %s", c.Score, c.Vector, c.Severity)
}

// SeverityToCvssScoreRange returns CVSS score range
func (c Cvss) SeverityToCvssScoreRange() string {
	return severityToCvssScoreRange(c.Severity)
}

func severityToCvssScoreRange(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "9.0-10.0"
	case "IMPORTANT", "HIGH":
		return "7.0-8.9"
	case "MODERATE", "MEDIUM":
		return "4.0-6.9"
	case "LOW", "NEGLIGIBLE":
		return "0.1-3.9"
	}
	return "None"
}

// Amazon Linux Security Advisory
// Critical, Important, Medium, Low
// https://alas.aws.amazon.com/
//
// RedHat, Oracle OVAL
// Critical, Important, Moderate, Low
// https://access.redhat.com/security/updates/classification
//
// Ubuntu OVAL
// Critical, High, Medium, Low
// https://wiki.ubuntu.com/Bugs/Importance
// https://people.canonical.com/~ubuntu-security/cve/priority.html
//
// Ubuntu CVE Tracker
// Critical, High, Medium, Low, Negligible
// https://people.canonical.com/~ubuntu-security/priority.html
func severityToCvssScoreRoughly(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 10.0
	case "IMPORTANT", "HIGH":
		return 8.9
	case "MODERATE", "MEDIUM":
		return 6.9
	case "LOW", "NEGLIGIBLE":
		return 3.9
	}
	return 0
}

// FormatMaxCvssScore returns Max CVSS Score
func (v VulnInfo) FormatMaxCvssScore() string {
	cvss := v.MaxCvssScore()
	return fmt.Sprintf("%3.1f %s (%s)",
		cvss.Value.Score,
		strings.ToUpper(cvss.Value.Severity),
		cvss.Type)
}

// DistroAdvisories is a list of DistroAdvisory
type DistroAdvisories []DistroAdvisory

// AppendIfMissing appends if missing
func (advs *DistroAdvisories) AppendIfMissing(adv *DistroAdvisory) bool {
	for _, a := range *advs {
		if a.AdvisoryID == adv.AdvisoryID {
			return false
		}
	}
	*advs = append(*advs, *adv)
	return true
}

// DistroAdvisory has Amazon Linux, RHEL, FreeBSD Security Advisory information.
type DistroAdvisory struct {
	AdvisoryID  string    `json:"advisoryID"`
	Severity    string    `json:"severity"`
	Issued      time.Time `json:"issued"`
	Updated     time.Time `json:"updated"`
	Description string    `json:"description"`
}

// Format the distro advisory information
func (p DistroAdvisory) Format() string {
	if p.AdvisoryID == "" {
		return ""
	}

	var delim bytes.Buffer
	for i := 0; i < len(p.AdvisoryID); i++ {
		delim.WriteString("-")
	}
	buf := []string{p.AdvisoryID, delim.String(), p.Description}
	return strings.Join(buf, "\n")
}

// Exploit :
type Exploit struct {
	ExploitType  exploitmodels.ExploitType `json:"exploitType"`
	ID           string                    `json:"id"`
	URL          string                    `json:"url"`
	Description  string                    `json:"description"`
	Verified     *bool                     `json:"verified,omitempty"`
	DocumentURL  *string                   `json:"documentURL,omitempty"`
	ShellCodeURL *string                   `json:"shellCodeURL,omitempty"`
	BinaryURL    *string                   `json:"binaryURL,omitempty"`
	PaperURL     *string                   `json:"paperURL,omitempty"`
	GHDBURL      *string                   `json:"ghdbURL,omitempty"`
}

// Metasploit :
type Metasploit struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description,omitempty"`
	URLs        []string `json:",omitempty"`
}

// Mitigation has a link and content
type Mitigation struct {
	CveContentType CveContentType `json:"cveContentType,omitempty"`
	Mitigation     string         `json:"mitigation,omitempty"`
	URL            string         `json:"url,omitempty"`
}

// KEVType :
type KEVType string

const (
	// CISAKEVType is CISA KEV
	CISAKEVType KEVType = "cisa"
	// VulnCheckKEVType is VulnCheck KEV
	VulnCheckKEVType KEVType = "vulncheck"
)

// KEV has CISA or VulnCheck Known Exploited Vulnerability
type KEV struct {
	Type                       KEVType    `json:"type,omitempty"`
	VendorProject              string     `json:"vendor_project,omitempty"`
	Product                    string     `json:"product,omitempty"`
	VulnerabilityName          string     `json:"vulnerability_name,omitempty"`
	ShortDescription           string     `json:"short_description,omitempty"`
	RequiredAction             string     `json:"required_action,omitempty"`
	KnownRansomwareCampaignUse string     `json:"known_ransomware_campaign_use,omitempty"`
	DateAdded                  time.Time  `json:"date_added,omitzero"`
	DueDate                    *time.Time `json:"due_date,omitempty"`

	CISA      *CISAKEV      `json:"cisa,omitempty"`
	VulnCheck *VulnCheckKEV `json:"vulncheck,omitempty"`
}

// CISAKEV has CISA KEV only data
type CISAKEV struct {
	Note string `json:"note,omitempty"`
}

// VulnCheckKEV has VulnCheck KEV only data
type VulnCheckKEV struct {
	XDB                  []VulnCheckXDB                  `json:"xdb,omitempty"`
	ReportedExploitation []VulnCheckReportedExploitation `json:"reported_exploitation,omitempty"`
}

// VulnCheckXDB :
type VulnCheckXDB struct {
	XDBID       string    `json:"xdb_id,omitempty"`
	XDBURL      string    `json:"xdb_url,omitempty"`
	DateAdded   time.Time `json:"date_added,omitzero"`
	ExploitType string    `json:"exploit_type,omitempty"`
	CloneSSHURL string    `json:"clone_ssh_url,omitempty"`
}

// VulnCheckReportedExploitation :
type VulnCheckReportedExploitation struct {
	URL       string    `json:"url,omitempty"`
	DateAdded time.Time `json:"date_added,omitzero"`
}

// AlertDict has target cve JPCERT and USCERT alert data
type AlertDict struct {
	CISA   []Alert `json:"cisa"` // backwards compatibility: for CISA KEV in old JSON
	JPCERT []Alert `json:"jpcert"`
	USCERT []Alert `json:"uscert"`
}

// IsEmpty checks if the content of AlertDict is empty
func (a AlertDict) IsEmpty() bool {
	return len(a.JPCERT) == 0 && len(a.USCERT) == 0
}

// FormatSource returns which source has this alert
func (a AlertDict) FormatSource() string {
	if len(a.USCERT) != 0 || len(a.JPCERT) != 0 {
		return "CERT"
	}
	return ""
}

// Confidences is a list of Confidence
type Confidences []Confidence

// AppendIfMissing appends confidence to the list if missing
func (cs *Confidences) AppendIfMissing(confidence Confidence) {
	for _, c := range *cs {
		if c.DetectionMethod == confidence.DetectionMethod {
			return
		}
	}
	*cs = append(*cs, confidence)
}

// SortByConfident sorts Confidences
func (cs Confidences) SortByConfident() Confidences {
	slices.SortFunc(cs, func(a, b Confidence) int {
		return cmp.Compare(a.SortOrder, b.SortOrder)
	})
	return cs
}

// Confidence is a ranking how confident the CVE-ID was detected correctly
// Score: 0 - 100
type Confidence struct {
	Score           int             `json:"score"`
	DetectionMethod DetectionMethod `json:"detectionMethod"`
	SortOrder       int             `json:"-"`
}

func (c Confidence) String() string {
	return fmt.Sprintf("%d / %s", c.Score, c.DetectionMethod)
}

// DetectionMethod indicates
// - How to detect the CveID
// - How to get the changelog difference between installed and candidate version
type DetectionMethod string

const (
	// NvdExactVersionMatchStr :
	NvdExactVersionMatchStr = "NvdExactVersionMatch"

	// NvdRoughVersionMatchStr :
	NvdRoughVersionMatchStr = "NvdRoughVersionMatch"

	// NvdVendorProductMatchStr :
	NvdVendorProductMatchStr = "NvdVendorProductMatch"

	// VulncheckExactVersionMatchStr :
	VulncheckExactVersionMatchStr = "VulncheckExactVersionMatch"

	// VulncheckRoughVersionMatchStr :
	VulncheckRoughVersionMatchStr = "VulncheckRoughVersionMatch"

	// VulncheckVendorProductMatchStr :
	VulncheckVendorProductMatchStr = "VulncheckVendorProductMatch"

	// JvnVendorProductMatchStr :
	JvnVendorProductMatchStr = "JvnVendorProductMatch"

	// FortinetExactVersionMatchStr :
	FortinetExactVersionMatchStr = "FortinetExactVersionMatch"

	// FortinetRoughVersionMatchStr :
	FortinetRoughVersionMatchStr = "FortinetRoughVersionMatch"

	// FortinetVendorProductMatchStr :
	FortinetVendorProductMatchStr = "FortinetVendorProductMatch"

	// PaloaltoExactVersionMatchStr :
	PaloaltoExactVersionMatchStr = "PaloaltoExactVersionMatch"

	// PaloaltoRoughVersionMatchStr :
	PaloaltoRoughVersionMatchStr = "PaloaltoRoughVersionMatch"

	// PaloaltoVendorProductMatchStr :
	PaloaltoVendorProductMatchStr = "PaloaltoVendorProductMatch"

	// CiscoExactVersionMatchStr :
	CiscoExactVersionMatchStr = "CiscoExactVersionMatch"

	// CiscoRoughVersionMatchStr :
	CiscoRoughVersionMatchStr = "CiscoRoughVersionMatch"

	// CiscoVendorProductMatchStr :
	CiscoVendorProductMatchStr = "CiscoVendorProductMatch"

	// PkgAuditMatchStr :
	PkgAuditMatchStr = "PkgAuditMatch"

	// OvalMatchStr :
	OvalMatchStr = "OvalMatch"

	// RedHatAPIStr is :
	RedHatAPIStr = "RedHatAPIMatch"

	// DebianSecurityTrackerMatchStr :
	DebianSecurityTrackerMatchStr = "DebianSecurityTrackerMatch"

	// UbuntuAPIMatchStr :
	UbuntuAPIMatchStr = "UbuntuAPIMatch"

	// WindowsUpdateSearchStr :
	WindowsUpdateSearchStr = "WindowsUpdateSearch"

	// WindowsRoughMatchStr :
	WindowsRoughMatchStr = "WindowsRoughMatch"

	// TrivyMatchStr :
	TrivyMatchStr = "TrivyMatch"

	// ChangelogExactMatchStr :
	ChangelogExactMatchStr = "ChangelogExactMatch"

	// ChangelogRoughMatchStr :
	ChangelogRoughMatchStr = "ChangelogRoughMatch"

	// GitHubMatchStr :
	GitHubMatchStr = "GitHubMatch"

	// WpScanMatchStr :
	WpScanMatchStr = "WpScanMatch"

	// FailedToGetChangelog :
	FailedToGetChangelog = "FailedToGetChangelog"

	// FailedToFindVersionInChangelog :
	FailedToFindVersionInChangelog = "FailedToFindVersionInChangelog"
)

var (
	// PkgAuditMatch is a ranking how confident the CVE-ID was detected correctly
	PkgAuditMatch = Confidence{100, PkgAuditMatchStr, 2}

	// OvalMatch is a ranking how confident the CVE-ID was detected correctly
	OvalMatch = Confidence{100, OvalMatchStr, 0}

	// RedHatAPIMatch is a ranking how confident the CVE-ID was detected correctly
	RedHatAPIMatch = Confidence{100, RedHatAPIStr, 0}

	// DebianSecurityTrackerMatch is a ranking how confident the CVE-ID was detected correctly
	DebianSecurityTrackerMatch = Confidence{100, DebianSecurityTrackerMatchStr, 0}

	// UbuntuAPIMatch is a ranking how confident the CVE-ID was detected correctly
	UbuntuAPIMatch = Confidence{100, UbuntuAPIMatchStr, 0}

	// WindowsUpdateSearch is a ranking how confident the CVE-ID was detected correctly
	WindowsUpdateSearch = Confidence{100, WindowsUpdateSearchStr, 0}

	// WindowsRoughMatch is a ranking how confident the CVE-ID was detected correctly
	WindowsRoughMatch = Confidence{30, WindowsRoughMatchStr, 0}

	// TrivyMatch is a ranking how confident the CVE-ID was detected correctly
	TrivyMatch = Confidence{100, TrivyMatchStr, 0}

	// ChangelogExactMatch is a ranking how confident the CVE-ID was detected correctly
	ChangelogExactMatch = Confidence{95, ChangelogExactMatchStr, 3}

	// ChangelogRoughMatch is a ranking how confident the CVE-ID was detected correctly
	ChangelogRoughMatch = Confidence{50, ChangelogRoughMatchStr, 4}

	// GitHubMatch is a ranking how confident the CVE-ID was detected correctly
	GitHubMatch = Confidence{100, GitHubMatchStr, 2}

	// WpScanMatch is a ranking how confident the CVE-ID was detected correctly
	WpScanMatch = Confidence{100, WpScanMatchStr, 0}

	// NvdExactVersionMatch is a ranking how confident the CVE-ID was detected correctly
	NvdExactVersionMatch = Confidence{100, NvdExactVersionMatchStr, 1}

	// NvdRoughVersionMatch is a ranking how confident the CVE-ID was detected correctly
	NvdRoughVersionMatch = Confidence{80, NvdRoughVersionMatchStr, 1}

	// NvdVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	NvdVendorProductMatch = Confidence{10, NvdVendorProductMatchStr, 9}

	// VulncheckExactVersionMatch is a ranking how confident the CVE-ID was detected correctly
	VulncheckExactVersionMatch = Confidence{85, VulncheckExactVersionMatchStr, 2}

	// VulncheckRoughVersionMatch is a ranking how confident the CVE-ID was detected correctly
	VulncheckRoughVersionMatch = Confidence{65, VulncheckRoughVersionMatchStr, 2}

	// VulncheckVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	VulncheckVendorProductMatch = Confidence{10, VulncheckVendorProductMatchStr, 9}

	// JvnVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	JvnVendorProductMatch = Confidence{10, JvnVendorProductMatchStr, 10}

	// FortinetExactVersionMatch is a ranking how confident the CVE-ID was detected correctly
	FortinetExactVersionMatch = Confidence{100, FortinetExactVersionMatchStr, 1}

	// FortinetRoughVersionMatch is a ranking how confident the CVE-ID was detected correctly
	FortinetRoughVersionMatch = Confidence{80, FortinetRoughVersionMatchStr, 1}

	// FortinetVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	FortinetVendorProductMatch = Confidence{10, FortinetVendorProductMatchStr, 9}

	// PaloaltoExactVersionMatch is a ranking how confident the CVE-ID was detected correctly
	PaloaltoExactVersionMatch = Confidence{100, PaloaltoExactVersionMatchStr, 1}

	// PaloaltoRoughVersionMatch is a ranking how confident the CVE-ID was detected correctly
	PaloaltoRoughVersionMatch = Confidence{80, PaloaltoRoughVersionMatchStr, 1}

	// PaloaltoVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	PaloaltoVendorProductMatch = Confidence{10, PaloaltoVendorProductMatchStr, 9}

	// CiscoExactVersionMatch is a ranking how confident the CVE-ID was detected correctly
	CiscoExactVersionMatch = Confidence{100, CiscoExactVersionMatchStr, 1}

	// CiscoRoughVersionMatch is a ranking how confident the CVE-ID was detected correctly
	CiscoRoughVersionMatch = Confidence{80, CiscoRoughVersionMatchStr, 1}

	// CiscoVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	CiscoVendorProductMatch = Confidence{10, CiscoVendorProductMatchStr, 9}
)
