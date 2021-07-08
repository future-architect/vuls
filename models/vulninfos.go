package models

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
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
func (v VulnInfos) FilterByCvssOver(over float64) VulnInfos {
	return v.Find(func(v VulnInfo) bool {
		if over <= v.MaxCvssScore().Value.Score {
			return true
		}
		return false
	})
}

// FilterIgnoreCves filter function.
func (v VulnInfos) FilterIgnoreCves(ignoreCveIDs []string) VulnInfos {
	return v.Find(func(v VulnInfo) bool {
		for _, c := range ignoreCveIDs {
			if v.CveID == c {
				return false
			}
		}
		return true
	})
}

// FilterUnfixed filter unfixed CVE-IDs
func (v VulnInfos) FilterUnfixed(ignoreUnfixed bool) VulnInfos {
	if !ignoreUnfixed {
		return v
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
		return !NotFixedAll
	})
}

// FilterIgnorePkgs is filter function.
func (v VulnInfos) FilterIgnorePkgs(ignorePkgsRegexps []string) VulnInfos {
	regexps := []*regexp.Regexp{}
	for _, pkgRegexp := range ignorePkgsRegexps {
		re, err := regexp.Compile(pkgRegexp)
		if err != nil {
			logging.Log.Warnf("Failed to parse %s. err: %+v", pkgRegexp, err)
			continue
		} else {
			regexps = append(regexps, re)
		}
	}
	if len(regexps) == 0 {
		return v
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
		return false
	})
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
		score := vInfo.MaxCvss3Score().Value.Score
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
		if vInfo.DiffStatus == DiffPlus {
			nPlus++
		} else if vInfo.DiffStatus == DiffMinus {
			nMinus++
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

// Sort by Name
func (ps PackageFixStatuses) Sort() {
	sort.Slice(ps, func(i, j int) bool {
		return ps[i].Name < ps[j].Name
	})
	return
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
	DistroAdvisories     DistroAdvisories     `json:"distroAdvisories,omitempty"` // for Amazon, RHEL, FreeBSD
	CveContents          CveContents          `json:"cveContents,omitempty"`
	Exploits             []Exploit            `json:"exploits,omitempty"`
	Metasploits          []Metasploit         `json:"metasploits,omitempty"`
	Mitigations          []Mitigation         `json:"mitigations,omitempty"`
	AlertDict            AlertDict            `json:"alertDict,omitempty"`
	CpeURIs              []string             `json:"cpeURIs,omitempty"` // CpeURIs related to this CVE defined in config.toml
	GitHubSecurityAlerts GitHubSecurityAlerts `json:"gitHubSecurityAlerts,omitempty"`
	WpPackageFixStats    WpPackageFixStats    `json:"wpPackageFixStats,omitempty"`
	LibraryFixedIns      LibraryFixedIns      `json:"libraryFixedIns,omitempty"`
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
	return fmt.Sprintf("%s", v.CveID)
}

// Titles returns title (TUI)
func (v VulnInfo) Titles(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if cont, found := v.CveContents[Jvn]; found && cont.Title != "" {
			values = append(values, CveContentStr{Jvn, cont.Title})
		}
	}

	// RedHat API has one line title.
	if cont, found := v.CveContents[RedHatAPI]; found && cont.Title != "" {
		values = append(values, CveContentStr{RedHatAPI, cont.Title})
	}

	// GitHub security alerts has a title.
	if cont, found := v.CveContents[GitHub]; found && cont.Title != "" {
		values = append(values, CveContentStr{GitHub, cont.Title})
	}

	order := CveContentTypes{Trivy, Nvd, NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order, Jvn)...)...)
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && cont.Summary != "" {
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
		if cont, found := v.CveContents[Jvn]; found && cont.Summary != "" {
			summary := cont.Title
			summary += "\n" + strings.Replace(
				strings.Replace(cont.Summary, "\n", " ", -1), "\r", " ", -1)
			values = append(values, CveContentStr{Jvn, summary})
		}
	}

	order := CveContentTypes{Trivy, NewCveContentType(myFamily), Nvd, GitHub}
	order = append(order, AllCveContetTypes.Except(append(order, Jvn)...)...)
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found && cont.Summary != "" {
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

	if v, ok := v.CveContents[WpScan]; ok {
		values = append(values, CveContentStr{
			Type:  WpScan,
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

// Cvss2Scores returns CVSS V2 Scores
func (v VulnInfo) Cvss2Scores() (values []CveContentCvss) {
	order := []CveContentType{RedHatAPI, RedHat, Nvd, Jvn}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found {
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
	return
}

// Cvss3Scores returns CVSS V3 Score
func (v VulnInfo) Cvss3Scores() (values []CveContentCvss) {
	order := []CveContentType{RedHatAPI, RedHat, Nvd, Jvn}
	for _, ctype := range order {
		if cont, found := v.CveContents[ctype]; found {
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

	for _, ctype := range []CveContentType{Debian, DebianSecurityTracker, Ubuntu, Amazon, Trivy, GitHub, WpScan} {
		if cont, found := v.CveContents[ctype]; found && cont.Cvss3Severity != "" {
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

	// Memo: Only RedHat, Oracle and Amazon has severity data in advisory.
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

// MaxCvssScore returns max CVSS Score
// If there is no CVSS Score, return Severity as a numerical value.
func (v VulnInfo) MaxCvssScore() CveContentCvss {
	v3Max := v.MaxCvss3Score()
	if v3Max.Type != Unknown {
		return v3Max
	}
	return v.MaxCvss2Score()
}

// MaxCvss3Score returns Max CVSS V3 Score
func (v VulnInfo) MaxCvss3Score() CveContentCvss {
	max := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS3},
	}
	for _, cvss := range v.Cvss3Scores() {
		if max.Value.Score < cvss.Value.Score {
			max = cvss
		}
	}
	return max
}

// MaxCvss2Score returns Max CVSS V2 Score
func (v VulnInfo) MaxCvss2Score() CveContentCvss {
	max := CveContentCvss{
		Type:  Unknown,
		Value: Cvss{Type: CVSS2},
	}
	for _, cvss := range v.Cvss2Scores() {
		if max.Value.Score < cvss.Value.Score {
			max = cvss
		}
	}
	return max
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
	case "LOW":
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
func severityToCvssScoreRoughly(severity string) float64 {
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

// AlertDict has target cve JPCERT and USCERT alert data
type AlertDict struct {
	Ja []Alert `json:"ja"`
	En []Alert `json:"en"`
}

// FormatSource returns which source has this alert
func (a AlertDict) FormatSource() string {
	if len(a.En) != 0 || len(a.Ja) != 0 {
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
	sort.Slice(cs, func(i, j int) bool {
		return cs[i].SortOrder < cs[j].SortOrder
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
	// CpeVersionMatchStr is a String representation of CpeNameMatch
	CpeVersionMatchStr = "CpeVersionMatch"

	// CpeVendorProductMatchStr is a String representation of CpeNameMatch
	CpeVendorProductMatchStr = "CpeVendorProductMatch"

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

	// UbuntuAPIMatchStr is a String representation of UbuntuAPIMatch
	UbuntuAPIMatchStr = "UbuntuAPIMatch"

	// TrivyMatchStr is a String representation of Trivy
	TrivyMatchStr = "TrivyMatch"

	// ChangelogExactMatchStr is a String representation of ChangelogExactMatch
	ChangelogExactMatchStr = "ChangelogExactMatch"

	// ChangelogLenientMatchStr is a String representation of ChangelogLenientMatch
	ChangelogLenientMatchStr = "ChangelogLenientMatch"

	// GitHubMatchStr is a String representation of GitHubMatch
	GitHubMatchStr = "GitHubMatch"

	// WpScanMatchStr is a String representation of WordPress VulnDB scanning
	WpScanMatchStr = "WpScanMatch"

	// FailedToGetChangelog is a String representation of FailedToGetChangelog
	FailedToGetChangelog = "FailedToGetChangelog"

	// FailedToFindVersionInChangelog is a String representation of FailedToFindVersionInChangelog
	FailedToFindVersionInChangelog = "FailedToFindVersionInChangelog"
)

var (
	// CpeVersionMatch is a ranking how confident the CVE-ID was detected correctly
	CpeVersionMatch = Confidence{100, CpeVersionMatchStr, 1}

	// YumUpdateSecurityMatch is a ranking how confident the CVE-ID was detected correctly
	YumUpdateSecurityMatch = Confidence{100, YumUpdateSecurityMatchStr, 2}

	// PkgAuditMatch is a ranking how confident the CVE-ID was detected correctly
	PkgAuditMatch = Confidence{100, PkgAuditMatchStr, 2}

	// OvalMatch is a ranking how confident the CVE-ID was detected correctly
	OvalMatch = Confidence{100, OvalMatchStr, 0}

	// RedHatAPIMatch ranking how confident the CVE-ID was detected correctly
	RedHatAPIMatch = Confidence{100, RedHatAPIStr, 0}

	// DebianSecurityTrackerMatch ranking how confident the CVE-ID was detected correctly
	DebianSecurityTrackerMatch = Confidence{100, DebianSecurityTrackerMatchStr, 0}

	// UbuntuAPIMatch ranking how confident the CVE-ID was detected correctly
	UbuntuAPIMatch = Confidence{100, UbuntuAPIMatchStr, 0}

	// TrivyMatch ranking how confident the CVE-ID was detected correctly
	TrivyMatch = Confidence{100, TrivyMatchStr, 0}

	// ChangelogExactMatch is a ranking how confident the CVE-ID was detected correctly
	ChangelogExactMatch = Confidence{95, ChangelogExactMatchStr, 3}

	// ChangelogLenientMatch is a ranking how confident the CVE-ID was detected correctly
	ChangelogLenientMatch = Confidence{50, ChangelogLenientMatchStr, 4}

	// GitHubMatch is a ranking how confident the CVE-ID was detected correctly
	GitHubMatch = Confidence{97, GitHubMatchStr, 2}

	// WpScanMatch is a ranking how confident the CVE-ID was detected correctly
	WpScanMatch = Confidence{100, WpScanMatchStr, 0}

	// CpeVendorProductMatch is a ranking how confident the CVE-ID was detected correctly
	CpeVendorProductMatch = Confidence{10, CpeVendorProductMatchStr, 9}
)
