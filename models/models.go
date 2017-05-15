/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

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

package models

import (
	"fmt"
	"strings"
	"time"

	cvedict "github.com/kotakanbe/go-cve-dictionary/models"
)

// JSONVersion is JSON Version
const JSONVersion = "0.3.0"

// ScanResults is slice of ScanResult.
type ScanResults []ScanResult

//TODO
//  // Len implement Sort Interface
//  func (s ScanResults) Len() int {
//      return len(s)
//  }

//  // Swap implement Sort Interface
//  func (s ScanResults) Swap(i, j int) {
//      s[i], s[j] = s[j], s[i]
//  }

//  // Less implement Sort Interface
//  func (s ScanResults) Less(i, j int) bool {
//      if s[i].ServerName == s[j].ServerName {
//          return s[i].Container.ContainerID < s[i].Container.ContainerID
//      }
//      return s[i].ServerName < s[j].ServerName
//  }

// ScanResult has the result of scanned CVE information.
type ScanResult struct {
	ScannedAt   time.Time
	JSONVersion string
	Lang        string
	ServerName  string // TOML Section key
	Family      string
	Release     string
	Container   Container
	Platform    Platform

	// Scanned Vulns by SSH scan + CPE + OVAL
	ScannedCves VulnInfos

	Packages Packages
	Errors   []string
	Optional [][]interface{}
}

// ConvertNvdToModel convert NVD to CveContent
func (r ScanResult) ConvertNvdToModel(cveID string, nvd cvedict.Nvd) *CveContent {
	var cpes []Cpe
	for _, c := range nvd.Cpes {
		cpes = append(cpes, Cpe{CpeName: c.CpeName})
	}

	var refs []Reference
	for _, r := range nvd.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	validVec := true
	for _, v := range []string{
		nvd.AccessVector,
		nvd.AccessComplexity,
		nvd.Authentication,
		nvd.ConfidentialityImpact,
		nvd.IntegrityImpact,
		nvd.AvailabilityImpact,
	} {
		if len(v) == 0 {
			validVec = false
		}
	}

	vector := ""
	if validVec {
		vector = fmt.Sprintf("AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s",
			string(nvd.AccessVector[0]),
			string(nvd.AccessComplexity[0]),
			string(nvd.Authentication[0]),
			string(nvd.ConfidentialityImpact[0]),
			string(nvd.IntegrityImpact[0]),
			string(nvd.AvailabilityImpact[0]))
	}

	//TODO CVSSv3
	return &CveContent{
		Type:         NVD,
		CveID:        cveID,
		Summary:      nvd.Summary,
		Cvss2Score:   nvd.Score,
		Cvss2Vector:  vector,
		Severity:     "", // severity is not contained in NVD
		SourceLink:   "https://nvd.nist.gov/vuln/detail/" + cveID,
		Cpes:         cpes,
		CweID:        nvd.CweID,
		References:   refs,
		Published:    nvd.PublishedDate,
		LastModified: nvd.LastModifiedDate,
	}
}

// ConvertJvnToModel convert JVN to CveContent
func (r ScanResult) ConvertJvnToModel(cveID string, jvn cvedict.Jvn) *CveContent {
	var cpes []Cpe
	for _, c := range jvn.Cpes {
		cpes = append(cpes, Cpe{CpeName: c.CpeName})
	}

	refs := []Reference{}
	for _, r := range jvn.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	vector := strings.TrimSuffix(strings.TrimPrefix(jvn.Vector, "("), ")")
	return &CveContent{
		Type:         JVN,
		CveID:        cveID,
		Title:        jvn.Title,
		Summary:      jvn.Summary,
		Severity:     jvn.Severity,
		Cvss2Score:   jvn.Score,
		Cvss2Vector:  vector,
		SourceLink:   jvn.JvnLink,
		Cpes:         cpes,
		References:   refs,
		Published:    jvn.PublishedDate,
		LastModified: jvn.LastModifiedDate,
	}
}

// FilterByCvssOver is filter function.
func (r ScanResult) FilterByCvssOver(over float64) ScanResult {
	// TODO: Set correct default value
	if over == 0 {
		over = -1.1
	}

	// TODO: Filter by ignore cves???
	filtered := r.ScannedCves.Find(func(v VulnInfo) bool {
		values := v.CveContents.Cvss2Scores()
		for _, v := range values {
			score := v.Value.Score
			if over <= score {
				return true
			}
		}
		return false
	})

	copiedScanResult := r
	copiedScanResult.ScannedCves = filtered
	return copiedScanResult
}

// ReportFileName returns the filename on localhost without extention
func (r ScanResult) ReportFileName() (name string) {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s", r.ServerName)
	}
	return fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
}

// ReportKeyName returns the name of key on S3, Azure-Blob without extention
func (r ScanResult) ReportKeyName() (name string) {
	timestr := r.ScannedAt.Format(time.RFC3339)
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s/%s", timestr, r.ServerName)
	}
	return fmt.Sprintf("%s/%s@%s", timestr, r.Container.Name, r.ServerName)
}

// ServerInfo returns server name one line
func (r ScanResult) ServerInfo() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
	}
	return fmt.Sprintf(
		"%s / %s (%s%s) on %s",
		r.Container.Name,
		r.Container.ContainerID,
		r.Family,
		r.Release,
		r.ServerName,
	)
}

// ServerInfoTui returns server infromation for TUI sidebar
func (r ScanResult) ServerInfoTui() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
	}
	return fmt.Sprintf(
		"|-- %s (%s%s)",
		r.Container.Name,
		r.Family,
		r.Release,
		//  r.Container.ContainerID,
	)
}

// FormatServerName returns server and container name
func (r ScanResult) FormatServerName() string {
	if len(r.Container.ContainerID) == 0 {
		return r.ServerName
	}
	return fmt.Sprintf("%s@%s",
		r.Container.Name, r.ServerName)
}

// CveSummary summarize the number of CVEs group by CVSSv2 Severity
func (r ScanResult) CveSummary(ignoreUnscoreCves bool) string {
	var high, medium, low, unknown int
	for _, vInfo := range r.ScannedCves {
		score := vInfo.CveContents.MaxCvss2Score().Value.Score
		if score < 0.1 {
			score = vInfo.CveContents.MaxCvss3Score().Value.Score
		}
		switch {
		case 7.0 <= score:
			high++
		case 4.0 <= score:
			medium++
		case 0 < score:
			low++
		default:
			unknown++
		}
	}

	if ignoreUnscoreCves {
		return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d)",
			high+medium+low, high, medium, low)
	}
	return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d ?:%d)",
		high+medium+low+unknown, high, medium, low, unknown)
}

// Confidence is a ranking how confident the CVE-ID was deteted correctly
// Score: 0 - 100
type Confidence struct {
	Score           int
	DetectionMethod string
}

func (c Confidence) String() string {
	return fmt.Sprintf("%d / %s", c.Score, c.DetectionMethod)
}

const (
	// CpeNameMatchStr is a String representation of CpeNameMatch
	CpeNameMatchStr = "CpeNameMatch"

	// YumUpdateSecurityMatchStr is a String representation of YumUpdateSecurityMatch
	YumUpdateSecurityMatchStr = "YumUpdateSecurityMatch"

	// PkgAuditMatchStr is a String representation of PkgAuditMatch
	PkgAuditMatchStr = "PkgAuditMatch"

	// OvalMatchStr is a String representation of OvalMatch
	OvalMatchStr = "OvalMatch"

	// ChangelogExactMatchStr is a String representation of ChangelogExactMatch
	ChangelogExactMatchStr = "ChangelogExactMatch"

	// ChangelogLenientMatchStr is a String representation of ChangelogLenientMatch
	ChangelogLenientMatchStr = "ChangelogLenientMatch"

	// FailedToGetChangelog is a String representation of FailedToGetChangelog
	FailedToGetChangelog = "FailedToGetChangelog"

	// FailedToFindVersionInChangelog is a String representation of FailedToFindVersionInChangelog
	FailedToFindVersionInChangelog = "FailedToFindVersionInChangelog"
)

var (
	// CpeNameMatch is a ranking how confident the CVE-ID was deteted correctly
	CpeNameMatch = Confidence{100, CpeNameMatchStr}

	// YumUpdateSecurityMatch is a ranking how confident the CVE-ID was deteted correctly
	YumUpdateSecurityMatch = Confidence{100, YumUpdateSecurityMatchStr}

	// PkgAuditMatch is a ranking how confident the CVE-ID was deteted correctly
	PkgAuditMatch = Confidence{100, PkgAuditMatchStr}

	// OvalMatch is a ranking how confident the CVE-ID was deteted correctly
	OvalMatch = Confidence{100, OvalMatchStr}

	// ChangelogExactMatch is a ranking how confident the CVE-ID was deteted correctly
	ChangelogExactMatch = Confidence{95, ChangelogExactMatchStr}

	// ChangelogLenientMatch is a ranking how confident the CVE-ID was deteted correctly
	ChangelogLenientMatch = Confidence{50, ChangelogLenientMatchStr}
)

// VulnInfos is VulnInfo list, getter/setter, sortable methods.
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

// VulnInfo holds a vulnerability information and unsecure packages
type VulnInfo struct {
	CveID            string
	Confidence       Confidence
	PackageNames     []string
	DistroAdvisories []DistroAdvisory // for Aamazon, RHEL, FreeBSD
	CpeNames         []string
	CveContents      CveContents
}

// Cvss2CalcURL returns CVSS v2 caluclator's URL
func (v VulnInfo) Cvss2CalcURL() string {
	return "https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=" + v.CveID
}

// Cvss3CalcURL returns CVSS v3 caluclator's URL
func (v VulnInfo) Cvss3CalcURL() string {
	return "https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?name=" + v.CveID
}

// TODO
// NilToEmpty set nil slice or map fields to empty to avoid null in JSON
//  func (v *VulnInfo) NilToEmpty() {
//      if v.CpeNames == nil {
//          v.CpeNames = []string{}
//      }
//      if v.DistroAdvisories == nil {
//          v.DistroAdvisories = []DistroAdvisory{}
//      }
//      if v.PackageNames == nil {
//          v.PackageNames = []string{}
//      }
//      if v.CveContents == nil {
//          v.CveContents = NewCveContents()
//      }
//  }

// CveContentType is a source of CVE information
type CveContentType string

// NewCveContentType create CveContentType
func NewCveContentType(name string) CveContentType {
	switch name {
	case "nvd":
		return NVD
	case "jvn":
		return JVN
	case "redhat", "centos":
		return RedHat
	case "ubuntu":
		return Ubuntu
	case "debian":
		return Debian
	default:
		return Unknown
	}
}

const (
	// NVD is NVD
	NVD CveContentType = "nvd"

	// JVN is JVN
	JVN CveContentType = "jvn"

	// RedHat is RedHat
	RedHat CveContentType = "redhat"

	// Debian is Debian
	Debian CveContentType = "debian"

	// Ubuntu is Ubuntu
	Ubuntu CveContentType = "ubuntu"

	// Unknown is Unknown
	Unknown CveContentType = "unknown"
)

// CveContentTypes has slide of CveContentType
type CveContentTypes []CveContentType

// AllCveContetTypes has all of CveContentTypes
var AllCveContetTypes = CveContentTypes{NVD, JVN, RedHat, Debian, Ubuntu}

// Except returns CveContentTypes except for given args
func (c CveContentTypes) Except(excepts ...CveContentType) (excepted CveContentTypes) {
	for _, ctype := range c {
		found := false
		for _, except := range excepts {
			if ctype == except {
				found = true
				break
			}
		}
		if !found {
			excepted = append(excepted, ctype)
		}
	}
	return
}

// CveContents has CveContent
type CveContents map[CveContentType]CveContent

// NewCveContents create CveContents
func NewCveContents(conts ...CveContent) CveContents {
	m := map[CveContentType]CveContent{}
	for _, cont := range conts {
		m[cont.Type] = cont
	}
	return m
}

// CveContentStr has CveContentType and Value
type CveContentStr struct {
	Type  CveContentType
	Value string
}

// Except returns CveContents except given keys for enumeration
func (v CveContents) Except(exceptCtypes ...CveContentType) (values CveContents) {
	for ctype, content := range v {
		found := false
		for _, exceptCtype := range exceptCtypes {
			if ctype == exceptCtype {
				found = true
				break
			}
		}
		if !found {
			values[ctype] = content
		}
	}
	return
}

// CveContentCvss2 has CveContentType and Cvss2
type CveContentCvss2 struct {
	Type  CveContentType
	Value Cvss2
}

// Cvss2 has CVSS v2
type Cvss2 struct {
	Score    float64
	Vector   string
	Severity string
}

func cvss2ScoreToSeverity(score float64) string {
	if 7.0 <= score {
		return "HIGH"
	} else if 4.0 <= score {
		return "MEDIUM"
	}
	return "LOW"
}

// Cvss2Scores returns CVSS V2 Scores
func (v CveContents) Cvss2Scores() (values []CveContentCvss2) {
	order := []CveContentType{NVD, RedHat, JVN}
	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < cont.Cvss2Score {
			// https://nvd.nist.gov/vuln-metrics/cvss
			sev := cont.Severity
			if ctype == NVD {
				sev = cvss2ScoreToSeverity(cont.Cvss2Score)
			}
			values = append(values, CveContentCvss2{
				Type: ctype,
				Value: Cvss2{
					Score:    cont.Cvss2Score,
					Vector:   cont.Cvss2Vector,
					Severity: sev,
				},
			})
		}
	}
	return
}

// MaxCvss2Score returns Max CVSS V2 Score
func (v CveContents) MaxCvss2Score() CveContentCvss2 {
	//TODO Severity Ubuntu, Debian...
	order := []CveContentType{NVD, RedHat, JVN}
	max := 0.0
	value := CveContentCvss2{
		Type:  Unknown,
		Value: Cvss2{},
	}
	for _, ctype := range order {
		if cont, found := v[ctype]; found && max < cont.Cvss2Score {
			// https://nvd.nist.gov/vuln-metrics/cvss
			sev := cont.Severity
			if ctype == NVD {
				sev = cvss2ScoreToSeverity(cont.Cvss2Score)
			}
			value = CveContentCvss2{
				Type: ctype,
				Value: Cvss2{
					Score:    cont.Cvss2Score,
					Vector:   cont.Cvss2Vector,
					Severity: sev,
				},
			}
			max = cont.Cvss2Score
		}
	}
	return value
}

// CveContentCvss3 has CveContentType and Cvss3
type CveContentCvss3 struct {
	Type  CveContentType
	Value Cvss3
}

// Cvss3 has CVSS v3
type Cvss3 struct {
	Score    float64
	Vector   string
	Severity string
}

func cvss3ScoreToSeverity(score float64) string {
	if 9.0 <= score {
		return "CRITICAL"
	} else if 7.0 <= score {
		return "HIGH"
	} else if 4.0 <= score {
		return "MEDIUM"
	}
	return "LOW"
}

// Cvss3Scores returns CVSS V3 Score
func (v CveContents) Cvss3Scores() (values []CveContentCvss3) {
	//TODO Severity Ubuntu, Debian...
	order := []CveContentType{RedHat}
	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < cont.Cvss3Score {
			// https://nvd.nist.gov/vuln-metrics/cvss
			sev := cont.Severity
			if ctype == NVD {
				sev = cvss3ScoreToSeverity(cont.Cvss2Score)
			}
			values = append(values, CveContentCvss3{
				Type: ctype,
				Value: Cvss3{
					Score:    cont.Cvss3Score,
					Vector:   cont.Cvss3Vector,
					Severity: sev,
				},
			})
		}
	}
	return
}

// MaxCvss3Score returns Max CVSS V3 Score
func (v CveContents) MaxCvss3Score() CveContentCvss3 {
	//TODO Severity Ubuntu, Debian...
	order := []CveContentType{RedHat}
	max := 0.0
	value := CveContentCvss3{
		Type:  Unknown,
		Value: Cvss3{},
	}
	for _, ctype := range order {
		if cont, found := v[ctype]; found && max < cont.Cvss3Score {
			// https://nvd.nist.gov/vuln-metrics/cvss
			sev := cont.Severity
			if ctype == NVD {
				sev = cvss3ScoreToSeverity(cont.Cvss2Score)
			}
			value = CveContentCvss3{
				Type: ctype,
				Value: Cvss3{
					Score:    cont.Cvss3Score,
					Vector:   cont.Cvss3Vector,
					Severity: sev,
				},
			}
			max = cont.Cvss3Score
		}
	}
	return value
}

// Titles returns tilte (TUI)
func (v CveContents) Titles(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if cont, found := v[JVN]; found && 0 < len(cont.Title) {
			values = append(values, CveContentStr{JVN, cont.Title})
		}
	}

	order := CveContentTypes{NVD, NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order, JVN)...)...)
	for _, ctype := range order {
		// Only JVN has meaningful title. so return first 100 char of summary
		if cont, found := v[ctype]; found && 0 < len(cont.Summary) {
			summary := strings.Replace(cont.Summary, "\n", " ", -1)
			index := 75
			if len(summary) < index {
				index = len(summary)
			}
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: summary[0:index] + "...",
			})
		}
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
func (v CveContents) Summaries(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if cont, found := v[JVN]; found && 0 < len(cont.Summary) {
			summary := cont.Title
			summary += "\n" + strings.Replace(
				strings.Replace(cont.Summary, "\n", " ", -1), "\r", " ", -1)
			values = append(values, CveContentStr{JVN, summary})
		}
	}

	order := CveContentTypes{NVD, NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order, JVN)...)...)
	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.Summary) {
			summary := strings.Replace(cont.Summary, "\n", " ", -1)
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: summary,
			})
		}
	}

	if len(values) == 0 {
		values = []CveContentStr{{
			Type:  Unknown,
			Value: "-",
		}}
	}
	return
}

// SourceLinks returns link of source
func (v CveContents) SourceLinks(lang, myFamily string) (values []CveContentStr) {
	if lang == "ja" {
		if cont, found := v[JVN]; found && !cont.Empty() {
			values = append(values, CveContentStr{JVN, cont.SourceLink})
		}
	}

	order := CveContentTypes{NVD, NewCveContentType(myFamily)}
	for _, ctype := range order {
		if cont, found := v[ctype]; found {
			values = append(values, CveContentStr{ctype, cont.SourceLink})
		}
	}
	return
}

// Severities returns Severities
//  func (v CveContents) Severities(myFamily string) (values []CveContentValue) {
//      order := CveContentTypes{NVD, NewCveContentType(myFamily)}
//      order = append(order, AllCveContetTypes.Except(append(order)...)...)

//      for _, ctype := range order {
//          if cont, found := v[ctype]; found && 0 < len(cont.Severity) {
//              values = append(values, CveContentValue{
//                  Type:  ctype,
//                  Value: cont.Severity,
//              })
//          }
//      }
//      return
//  }

// CveContentCpes has CveContentType and Value
type CveContentCpes struct {
	Type  CveContentType
	Value []Cpe
}

// Cpes returns affected CPEs of this Vulnerability
func (v CveContents) Cpes(myFamily string) (values []CveContentCpes) {
	order := CveContentTypes{NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order)...)...)

	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.Cpes) {
			values = append(values, CveContentCpes{
				Type:  ctype,
				Value: cont.Cpes,
			})
		}
	}
	return
}

// CveContentRefs has CveContentType and Cpes
type CveContentRefs struct {
	Type  CveContentType
	Value []Reference
}

// References returns References
func (v CveContents) References(myFamily string) (values []CveContentRefs) {
	order := CveContentTypes{NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order)...)...)

	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.References) {
			values = append(values, CveContentRefs{
				Type:  ctype,
				Value: cont.References,
			})
		}
	}
	return
}

// CweIDs returns CweIDs
func (v CveContents) CweIDs(myFamily string) (values []CveContentStr) {
	order := CveContentTypes{NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order)...)...)

	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.CweID) {
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: cont.CweID,
			})
		}
	}
	return
}

// CveContent has abstraction of various vulnerability information
type CveContent struct {
	Type         CveContentType
	CveID        string
	Title        string
	Summary      string
	Severity     string
	Cvss2Score   float64
	Cvss2Vector  string
	Cvss3Score   float64
	Cvss3Vector  string
	SourceLink   string
	Cpes         []Cpe
	References   References
	CweID        string
	Published    time.Time
	LastModified time.Time
}

// Empty checks the content is empty
func (c CveContent) Empty() bool {
	return c.Summary == ""
}

// Cpe is Common Platform Enumeration
type Cpe struct {
	CpeName string
}

// References is a slice of Reference
type References []Reference

// Find elements that matches the function passed in argument
func (r References) Find(f func(r Reference) bool) (refs []Reference) {
	for _, rr := range r {
		refs = append(refs, rr)
	}
	return
}

// Reference has a related link of the CVE
type Reference struct {
	Source string
	Link   string
	RefID  string
}

// Packages is Map of Package
// { "package-name": Package }
type Packages map[string]Package

// NewPackages create Packages
func NewPackages(packs ...Package) Packages {
	m := Packages{}
	for _, pack := range packs {
		m[pack.Name] = pack
	}
	return m
}

// MergeNewVersion merges candidate version information to the receiver struct
func (ps Packages) MergeNewVersion(as Packages) {
	for _, a := range as {
		if pack, ok := ps[a.Name]; ok {
			pack.NewVersion = a.NewVersion
			pack.NewRelease = a.NewRelease
			ps[a.Name] = pack
		}
	}
}

// Merge returns merged map (immutable)
func (ps Packages) Merge(other Packages) Packages {
	merged := map[string]Package{}
	for k, v := range ps {
		merged[k] = v
	}
	for k, v := range other {
		merged[k] = v
	}
	return merged
}

// FormatVersionsFromTo returns updatable packages
func (ps Packages) FormatVersionsFromTo() string {
	ss := []string{}
	for _, pack := range ps {
		ss = append(ss, pack.FormatVersionFromTo())
	}
	return strings.Join(ss, "\n")
}

// FormatUpdatablePacksSummary returns a summary of updatable packages
func (ps Packages) FormatUpdatablePacksSummary() string {
	nUpdatable := 0
	for _, p := range ps {
		if p.NewVersion != "" {
			nUpdatable++
		}
	}
	return fmt.Sprintf("%d updatable packages", nUpdatable)
}

// Package has installed packages.
type Package struct {
	Name        string
	Version     string
	Release     string
	NewVersion  string
	NewRelease  string
	Repository  string
	Changelog   Changelog
	NotFixedYet bool // Ubuntu OVAL Only
}

// FormatVer returns package name-version-release
func (p Package) FormatVer() string {
	str := p.Name
	if 0 < len(p.Version) {
		str = fmt.Sprintf("%s-%s", str, p.Version)
	}
	if 0 < len(p.Release) {
		str = fmt.Sprintf("%s-%s", str, p.Release)
	}
	return str
}

// FormatNewVer returns package name-version-release
func (p Package) FormatNewVer() string {
	str := p.Name
	if 0 < len(p.NewVersion) {
		str = fmt.Sprintf("%s-%s", str, p.NewVersion)
	}
	if 0 < len(p.NewRelease) {
		str = fmt.Sprintf("%s-%s", str, p.NewRelease)
	}
	return str
}

// FormatVersionFromTo formats installed and new package version
func (p Package) FormatVersionFromTo() string {
	return fmt.Sprintf("%s -> %s", p.FormatVer(), p.FormatNewVer())
}

// Changelog has contents of changelog and how to get it.
// Method: modesl.detectionMethodStr
type Changelog struct {
	Contents string
	Method   string
}

// DistroAdvisory has Amazon Linux, RHEL, FreeBSD Security Advisory information.
type DistroAdvisory struct {
	AdvisoryID string
	Severity   string
	Issued     time.Time
	Updated    time.Time
}

// Container has Container information
type Container struct {
	ContainerID string
	Name        string
	Image       string
	Type        string
}

// Platform has platform information
type Platform struct {
	Name       string // aws or azure or gcp or other...
	InstanceID string
}
