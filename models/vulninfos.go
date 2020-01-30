package models

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	exploitmodels "github.com/mozqnet/go-exploitdb/models"
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

// FindScoredVulns return scored vulnerabilities
func (v VulnInfos) FindScoredVulns() VulnInfos {
	return v.Find(func(vv VulnInfo) bool {
		if 0 < vv.MaxCvss2Score().Value.Score ||
			0 < vv.MaxCvss3Score().Value.Score {
			return true
		}
		return false
	})
}

// ToSortedSlice returns slice of VulnInfos that is sorted by Score, CVE-ID
func (v VulnInfos) ToSortedSlice() (sorted []VulnInfo) {
	for k := range v {
		sorted = append(sorted, v[k])
	}
	sort.Slice(sorted, func(i, j int) bool {
		maxI := sorted[i].MaxCvssScore()
		maxJ := sorted[j].MaxCvssScore()
		if maxI.Value.Score != maxJ.Value.Score {
			return maxJ.Value.Score < maxI.Value.Score
		}
		return sorted[i].CveID < sorted[j].CveID
	})
	return
}

// CountGroupBySeverity summarize the number of CVEs group by CVSSv2 Severity
func (v VulnInfos) CountGroupBySeverity() map[string]int {
	m := map[string]int{}
	for _, vInfo := range v {
		score := vInfo.MaxCvss2Score().Value.Score
		if score < 0.1 {
			score = vInfo.MaxCvss3Score().Value.Score
		}
		switch {
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

	if config.Conf.IgnoreUnscoredCves {
		return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d)",
			m["High"]+m["Medium"]+m["Low"], m["High"], m["Medium"], m["Low"])
	}
	return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d ?:%d)",
		m["High"]+m["Medium"]+m["Low"]+m["Unknown"],
		m["High"], m["Medium"], m["Low"], m["Unknown"])
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

// Sort by Name
func (ps PackageFixStatuses) Sort() {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Name < ps[j].Name
	})
	return
}

// PackageFixStatus has name and other status abount the package
type PackageFixStatus struct {
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet"`
	FixState    string `json:"fixState"`
}

// VulnInfo has a vulnerability information and unsecure packages
type VulnInfo struct {
	CveID                string               `json:"cveID,omitempty"`
	Confidences          Confidences          `json:"confidences,omitempty"`
	AffectedPackages     PackageFixStatuses   `json:"affectedPackages,omitempty"`
	DistroAdvisories     DistroAdvisories     `json:"distroAdvisories,omitempty"` // for Aamazon, RHEL, FreeBSD
	CveContents          CveContents          `json:"cveContents,omitempty"`
	Exploits             []Exploit            `json:"exploits,omitempty"`
	AlertDict            AlertDict            `json:"alertDict,omitempty"`
	CpeURIs              []string             `json:"cpeURIs,omitempty"` // CpeURIs related to this CVE defined in config.toml
	GitHubSecurityAlerts GitHubSecurityAlerts `json:"gitHubSecurityAlerts,omitempty"`
	WpPackageFixStats    WpPackageFixStats    `json:"wpPackageFixStats,omitempty"`
	LibraryFixedIns      LibraryFixedIns      `json:"libraryFixedIns,omitempty"`

	VulnType string `json:"vulnType,omitempty"`
}

// Alert has XCERT alert information
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
		if a.PackageName == alert.PackageName {
			return g
		}
	}
	return append(g, alert)
}

// Names return a slice of lib names
func (g GitHubSecurityAlerts) Names() (names []string) {
	for _, a := range g {
		names = append(names, a.PackageName)
	}
	return names
}

// GitHubSecurityAlert has detected CVE-ID, PackageName, Status fetched via GitHub API
type GitHubSecurityAlert struct {
	PackageName   string    `json:"packageName"`
	FixedIn       string    `json:"fixedIn"`
	AffectedRange string    `json:"affectedRange"`
	Dismissed     bool      `json:"dismissed"`
	DismissedAt   time.Time `json:"dismissedAt"`
	DismissReason string    `json:"dismissReason"`
}

// LibraryFixedIns is a list of Library's FixedIn
type LibraryFixedIns []LibraryFixedIn

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

// Titles returns tilte (TUI)
func (v VulnInfo) Titles(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if cont, found := v.CveContents[Jvn]; found && 0 < len(cont.Title) {
			values = append(values, CveContentStr{Jvn, cont.Title})
		}
	}

	// RedHat API has one line title.
	if cont, found := v.CveContents[RedHatAPI]; found && 0 < len(cont.Title) {
		values = append(values, CveContentStr{RedHatAPI, cont.Title})
	}

	order := CveContentTypes{Nvd, NvdXML, NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order, Jvn)...)...)
	for _, ctype := range order {
		// Only JVN has meaningful title. so return first 100 char of summary
		if cont, found := v.CveContents[ctype]; found && 0 < len(cont.Summary) {
			summary := strings.Replace(cont.Summary, "\n", " ", -1)
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: summary,
			})
		}
	}

	for _, adv := range v.DistroAdvisories {
		values = append(values, CveContentStr{
			Type:  "Vendor",
			Value: strings.Replace(adv.Description, "\n", " ", -1),
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
		if cont, found := v.CveContents[Jvn]; found && 0 < len(cont.Summary) {
			summary := cont.Title
			summary += "\n" + strings.Replace(
				strings.Replace(cont.Summary, "\n", " ", -1), "\r", " ", -1)
			values = append(values, CveContentStr{Jvn, summary})
		}
	}

	order := CveContentTypes{NewCveContentType(myFamily), Nvd, NvdXML}
	order = append(order, AllCveContetTypes.Except(append(order, Jvn)...)...)
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && 0 < len(cont.Summary) {
			summary := strings.Replace(cont.Summary, "\n", " ", -1)
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: summary,
			})
		}
	}

	for _, adv := range v.DistroAdvisories {
		values = append(values, CveContentStr{
			Type:  "Vendor",
			Value: adv.Description,
		})
	}

	if v, ok := v.CveContents[WPVulnDB]; ok {
		values = append(values, CveContentStr{
			Type:  "WPVDB",
			Value: v.Title,
		})
	}

	if len(values) == 0 {
		return []CveContentStr{{
			Type:  Unknown,
			Value: "-",
		}}
	}

	return
}

// Mitigations returns mitigations
func (v VulnInfo) Mitigations(myFamily string) (values []CveContentStr) {
	order := CveContentTypes{RedHatAPI}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && 0 < len(cont.Mitigation) {
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: cont.Mitigation,
			})
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
func (v VulnInfo) Cvss2Scores(myFamily string) (values []CveContentCvss) {
	order := []CveContentType{Nvd, NvdXML, RedHatAPI, RedHat, Jvn}
	if myFamily != config.RedHat && myFamily != config.CentOS {
		order = append(order, NewCveContentType(myFamily))
	}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found {
			if cont.Cvss2Score == 0 || cont.Cvss2Severity == "" {
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

	for _, adv := range v.DistroAdvisories {
		if adv.Severity != "" {
			values = append(values, CveContentCvss{
				Type: "Advisory",
				Value: Cvss{
					Type:                 CVSS2,
					Score:                severityToV2ScoreRoughly(adv.Severity),
					CalculatedBySeverity: true,
					Vector:               "-",
					Severity:             strings.ToUpper(adv.Severity),
				},
			})
		}
	}

	// An OVAL entry in Ubuntu and Debian has only severity (CVSS score isn't included).
	// Show severity and dummy score calculated roughly.
	order = append(order, AllCveContetTypes.Except(order...)...)
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found &&
			cont.Cvss2Score == 0 &&
			cont.Cvss3Score == 0 &&
			cont.Cvss2Severity != "" {

			values = append(values, CveContentCvss{
				Type: cont.Type,
				Value: Cvss{
					Type:                 CVSS2,
					Score:                severityToV2ScoreRoughly(cont.Cvss2Severity),
					CalculatedBySeverity: true,
					Vector:               "-",
					Severity:             strings.ToUpper(cont.Cvss2Severity),
				},
			})
		}
	}

	return
}

// Cvss3Scores returns CVSS V3 Score
func (v VulnInfo) Cvss3Scores() (values []CveContentCvss) {
	order := []CveContentType{Nvd, RedHatAPI, RedHat, Jvn}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found {
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
	return
}

// MaxCvss3Score returns Max CVSS V3 Score
func (v VulnInfo) MaxCvss3Score() CveContentCvss {
	order := []CveContentType{Nvd, RedHat, RedHatAPI, Jvn}
	max := 0.0
	value := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS3},
	}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && max < cont.Cvss3Score {
			// https://nvd.nist.gov/vuln-metrics/cvss
			value = CveContentCvss{
				Type: ctype,
				Value: Cvss{
					Type:     CVSS3,
					Score:    cont.Cvss3Score,
					Vector:   cont.Cvss3Vector,
					Severity: strings.ToUpper(cont.Cvss3Severity),
				},
			}
			max = cont.Cvss3Score
		}
	}
	return value
}

// MaxCvssScore returns max CVSS Score
// If there is no CVSS Score, return Severity as a numerical value.
func (v VulnInfo) MaxCvssScore() CveContentCvss {
	v3Max := v.MaxCvss3Score()
	v2Max := v.MaxCvss2Score()
	max := v3Max
	if max.Type == Unknown {
		return v2Max
	}

	if max.Value.Score < v2Max.Value.Score && !v2Max.Value.CalculatedBySeverity {
		max = v2Max
	}
	return max
}

// MaxCvss2Score returns Max CVSS V2 Score
func (v VulnInfo) MaxCvss2Score() CveContentCvss {
	order := []CveContentType{Nvd, NvdXML, RedHat, RedHatAPI, Jvn}
	max := 0.0
	value := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS2},
	}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && max < cont.Cvss2Score {
			// https://nvd.nist.gov/vuln-metrics/cvss
			value = CveContentCvss{
				Type: ctype,
				Value: Cvss{
					Type:     CVSS2,
					Score:    cont.Cvss2Score,
					Vector:   cont.Cvss2Vector,
					Severity: strings.ToUpper(cont.Cvss2Severity),
				},
			}
			max = cont.Cvss2Score
		}
	}
	if 0 < max {
		return value
	}

	// If CVSS score isn't on NVD, RedHat and JVN, use OVAL and advisory Severity.
	// Convert severity to cvss srore roughly, then returns max severity.
	// Only Ubuntu, RedHat and Oracle have severity data in OVAL.
	order = []CveContentType{Ubuntu, RedHat, Oracle}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && 0 < len(cont.Cvss2Severity) {
			score := severityToV2ScoreRoughly(cont.Cvss2Severity)
			if max < score {
				value = CveContentCvss{
					Type: ctype,
					Value: Cvss{
						Type:                 CVSS2,
						Score:                score,
						CalculatedBySeverity: true,
						Vector:               cont.Cvss2Vector,
						Severity:             strings.ToUpper(cont.Cvss2Severity),
					},
				}
			}
			max = score
		}
	}

	// Only RedHat, Oracle and Amazon has severity data in advisory.
	for _, adv := range v.DistroAdvisories {
		if adv.Severity != "" {
			score := severityToV2ScoreRoughly(adv.Severity)
			if max < score {
				value = CveContentCvss{
					Type: "Vendor",
					Value: Cvss{
						Type:                 CVSS2,
						Score:                score,
						CalculatedBySeverity: true,
						Vector:               "-",
						Severity:             adv.Severity,
					},
				}
			}
		}
	}
	return value
}

// AttackVector returns attack vector string
func (v VulnInfo) AttackVector() string {
	for _, cnt := range v.CveContents {
		if strings.HasPrefix(cnt.Cvss2Vector, "AV:N") ||
			strings.Contains(cnt.Cvss3Vector, "AV:N") {
			return "AV:N"
		} else if strings.HasPrefix(cnt.Cvss2Vector, "AV:A") ||
			strings.Contains(cnt.Cvss3Vector, "AV:A") {
			return "AV:A"
		} else if strings.HasPrefix(cnt.Cvss2Vector, "AV:L") ||
			strings.Contains(cnt.Cvss3Vector, "AV:L") {
			return "AV:L"
		} else if strings.Contains(cnt.Cvss3Vector, "AV:P") {
			// no AV:P in CVSS v2
			return "AV:P"
		}
	}
	if cont, found := v.CveContents[DebianSecurityTracker]; found {
		if attackRange, found := cont.Optional["attack range"]; found {
			return attackRange
		}
	}
	return ""
}

// PatchStatus returns fixed or unfixed string
func (v VulnInfo) PatchStatus(packs Packages) string {
	// Vuls don't know patch status of the CPE
	if len(v.CpeURIs) != 0 {
		return ""
	}
	for _, p := range v.AffectedPackages {
		if p.NotFixedYet {
			return "unfixed"
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
	// CVSS2 means CVSS vesion2
	CVSS2 CvssType = "2"

	// CVSS3 means CVSS vesion3
	CVSS3 CvssType = "3"
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
	if c.Score == 0 || c.Vector == "" {
		return c.Severity
	}
	switch c.Type {
	case CVSS2:
		return fmt.Sprintf("%3.1f/%s %s", c.Score, c.Vector, c.Severity)
	case CVSS3:
		return fmt.Sprintf("%3.1f/%s %s", c.Score, c.Vector, c.Severity)
	}
	return ""
}

func cvss2ScoreToSeverity(score float64) string {
	if 7.0 <= score {
		return "HIGH"
	} else if 4.0 <= score {
		return "MEDIUM"
	}
	return "LOW"
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
func severityToV2ScoreRoughly(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 10.0
	case "IMPORTANT", "HIGH":
		return 8.9
	case "MODERATE", "MEDIUM":
		return 6.9
	case "LOW":
		return 3.9
	}
	return 0
}

// FormatMaxCvssScore returns Max CVSS Score
func (v VulnInfo) FormatMaxCvssScore() string {
	max := v.MaxCvssScore()
	return fmt.Sprintf("%3.1f %s (%s)",
		max.Value.Score,
		strings.ToUpper(max.Value.Severity),
		max.Type)
}

// Cvss2CalcURL returns CVSS v2 caluclator's URL
func (v VulnInfo) Cvss2CalcURL() string {
	return "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=" + v.CveID
}

// Cvss3CalcURL returns CVSS v3 caluclator's URL
func (v VulnInfo) Cvss3CalcURL() string {
	return "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=" + v.CveID
}

// VendorLinks returns links of vendor support's URL
func (v VulnInfo) VendorLinks(family string) map[string]string {
	links := map[string]string{}
	if strings.HasPrefix(v.CveID, "WPVDBID") {
		links["WPVulnDB"] = fmt.Sprintf("https://wpvulndb.com/vulnerabilities/%s",
			strings.TrimPrefix(v.CveID, "WPVDBID-"))
		return links
	}

	switch family {
	case config.RedHat, config.CentOS:
		links["RHEL-CVE"] = "https://access.redhat.com/security/cve/" + v.CveID
		for _, advisory := range v.DistroAdvisories {
			aidURL := strings.Replace(advisory.AdvisoryID, ":", "-", -1)
			links[advisory.AdvisoryID] = fmt.Sprintf("https://rhn.redhat.com/errata/%s.html", aidURL)
		}
		return links
	case config.Oracle:
		links["Oracle-CVE"] = fmt.Sprintf("https://linux.oracle.com/cve/%s.html", v.CveID)
		for _, advisory := range v.DistroAdvisories {
			links[advisory.AdvisoryID] =
				fmt.Sprintf("https://linux.oracle.com/errata/%s.html", advisory.AdvisoryID)
		}
		return links
	case config.Amazon:
		links["RHEL-CVE"] = "https://access.redhat.com/security/cve/" + v.CveID
		for _, advisory := range v.DistroAdvisories {
			if strings.HasPrefix(advisory.AdvisoryID, "ALAS2") {
				links[advisory.AdvisoryID] =
					fmt.Sprintf("https://alas.aws.amazon.com/AL2/%s.html",
						strings.Replace(advisory.AdvisoryID, "ALAS2", "ALAS", -1))
			} else {
				links[advisory.AdvisoryID] =
					fmt.Sprintf("https://alas.aws.amazon.com/%s.html", advisory.AdvisoryID)
			}
		}
		return links
	case config.Ubuntu:
		links["Ubuntu-CVE"] = "http://people.ubuntu.com/~ubuntu-security/cve/" + v.CveID
		return links
	case config.Debian:
		links["Debian-CVE"] = "https://security-tracker.debian.org/tracker/" + v.CveID
	case config.SUSEEnterpriseServer:
		links["SUSE-CVE"] = "https://www.suse.com/security/cve/" + v.CveID
	case config.FreeBSD:
		for _, advisory := range v.DistroAdvisories {
			links["FreeBSD-VuXML"] = fmt.Sprintf("https://vuxml.freebsd.org/freebsd/%s.html", advisory.AdvisoryID)

		}
		return links
	}
	return links
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
	DocumentURL  *string                   `json:"documentURL,omitempty"`
	ShellCodeURL *string                   `json:"shellCodeURL,omitempty"`
	BinaryURL    *string                   `json:"binaryURL,omitempty"`
}

// AlertDict has target cve's JPCERT and USCERT alert data
type AlertDict struct {
	Ja []Alert `json:"ja"`
	En []Alert `json:"en"`
}

// FormatSource returns which source has this alert
func (a AlertDict) FormatSource() string {
	s := []string{}
	if len(a.En) != 0 {
		s = append(s, "USCERT")
	}
	if len(a.Ja) != 0 {
		s = append(s, "JPCERT")
	}
	return strings.Join(s, "/")
}

// Confidences is a list of Confidence
type Confidences []Confidence

// AppendIfMissing appends confidence to the list if missiong
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
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].SortOrder < cs[j].SortOrder
	})
	return cs
}

// Confidence is a ranking how confident the CVE-ID was deteted correctly
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
	// CpeNameMatchStr is a String representation of CpeNameMatch
	CpeNameMatchStr = "CpeNameMatch"

	// YumUpdateSecurityMatchStr is a String representation of YumUpdateSecurityMatch
	YumUpdateSecurityMatchStr = "YumUpdateSecurityMatch"

	// PkgAuditMatchStr is a String representation of PkgAuditMatch
	PkgAuditMatchStr = "PkgAuditMatch"

	// OvalMatchStr is a String representation of OvalMatch
	OvalMatchStr = "OvalMatch"

	// RedHatAPIStr is a String representation of RedHatAPIMatch
	RedHatAPIStr = "RedHatAPIMatch"

	// DebianSecurityTrackerMatchStr is a String representation of DebianSecurityTrackerMatch
	DebianSecurityTrackerMatchStr = "DebianSecurityTrackerMatch"

	// ChangelogExactMatchStr is a String representation of ChangelogExactMatch
	ChangelogExactMatchStr = "ChangelogExactMatch"

	// ChangelogLenientMatchStr is a String representation of ChangelogLenientMatch
	ChangelogLenientMatchStr = "ChangelogLenientMatch"

	// GitHubMatchStr is a String representation of GitHubMatch
	GitHubMatchStr = "GitHubMatch"

	// WPVulnDBMatchStr is a String representation of WordPress VulnDB scanning
	WPVulnDBMatchStr = "WPVulnDBMatch"

	// FailedToGetChangelog is a String representation of FailedToGetChangelog
	FailedToGetChangelog = "FailedToGetChangelog"

	// FailedToFindVersionInChangelog is a String representation of FailedToFindVersionInChangelog
	FailedToFindVersionInChangelog = "FailedToFindVersionInChangelog"
)

var (
	// CpeNameMatch is a ranking how confident the CVE-ID was deteted correctly
	CpeNameMatch = Confidence{100, CpeNameMatchStr, 1}

	// YumUpdateSecurityMatch is a ranking how confident the CVE-ID was deteted correctly
	YumUpdateSecurityMatch = Confidence{100, YumUpdateSecurityMatchStr, 2}

	// PkgAuditMatch is a ranking how confident the CVE-ID was deteted correctly
	PkgAuditMatch = Confidence{100, PkgAuditMatchStr, 2}

	// OvalMatch is a ranking how confident the CVE-ID was deteted correctly
	OvalMatch = Confidence{100, OvalMatchStr, 0}

	// RedHatAPIMatch ranking how confident the CVE-ID was deteted correctly
	RedHatAPIMatch = Confidence{100, RedHatAPIStr, 0}

	// DebianSecurityTrackerMatch ranking how confident the CVE-ID was deteted correctly
	DebianSecurityTrackerMatch = Confidence{100, DebianSecurityTrackerMatchStr, 0}

	// ChangelogExactMatch is a ranking how confident the CVE-ID was deteted correctly
	ChangelogExactMatch = Confidence{95, ChangelogExactMatchStr, 3}

	// ChangelogLenientMatch is a ranking how confident the CVE-ID was deteted correctly
	ChangelogLenientMatch = Confidence{50, ChangelogLenientMatchStr, 4}

	// GitHubMatch is a ranking how confident the CVE-ID was deteted correctly
	GitHubMatch = Confidence{97, GitHubMatchStr, 2}

	// WPVulnDBMatch is a ranking how confident the CVE-ID was deteted correctly
	WPVulnDBMatch = Confidence{100, WPVulnDBMatchStr, 0}
)
