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
	"sort"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
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

// FindScoredVulns return scored vulnerabilities
func (v VulnInfos) FindScoredVulns() VulnInfos {
	return v.Find(func(vv VulnInfo) bool {
		if 0 < vv.CveContents.MaxCvss2Score().Value.Score ||
			0 < vv.CveContents.MaxCvss3Score().Value.Score {
			return true
		}
		return false
	})
}

// ToSortedSlice returns slice of VulnInfos that is sorted by CVE-ID
func (v VulnInfos) ToSortedSlice() (sorted []VulnInfo) {
	for k := range v {
		sorted = append(sorted, v[k])
	}
	sort.Slice(sorted, func(i, j int) bool {
		maxI := sorted[i].CveContents.MaxCvssScore()
		maxJ := sorted[j].CveContents.MaxCvssScore()
		if maxI != maxJ {
			return maxJ < maxI
		}
		return sorted[i].CveID < sorted[j].CveID
	})
	return
}

// CountGroupBySeverity summarize the number of CVEs group by CVSSv2 Severity
func (v VulnInfos) CountGroupBySeverity() map[string]int {
	m := map[string]int{}
	for _, vInfo := range v {
		score := vInfo.CveContents.MaxCvss2Score().Value.Score
		if score < 0.1 {
			score = vInfo.CveContents.MaxCvss3Score().Value.Score
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

// VulnInfo has a vulnerability information and unsecure packages
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

// VendorLinks returns links of vendor support's URL
func (v VulnInfo) VendorLinks(family string) map[string]string {
	links := map[string]string{}
	switch family {
	case "rhel", "centos":
		links["RHEL-CVE"] = "https://access.redhat.com/security/cve/" + v.CveID
		for _, advisory := range v.DistroAdvisories {
			aidURL := strings.Replace(advisory.AdvisoryID, ":", "-", -1)
			links[advisory.AdvisoryID] = fmt.Sprintf("https://rhn.redhat.com/errata/%s.html", aidURL)
		}
		return links
	case "oraclelinux":
		links["Oracle-CVE"] = fmt.Sprintf("https://linux.oracle.com/cve/%s.html", v.CveID)
		for _, advisory := range v.DistroAdvisories {
			links[advisory.AdvisoryID] =
				fmt.Sprintf("https://linux.oracle.com/errata/%s.html", advisory.AdvisoryID)
		}
		return links
	case "amazon":
		links["RHEL-CVE"] = "https://access.redhat.com/security/cve/" + v.CveID
		for _, advisory := range v.DistroAdvisories {
			links[advisory.AdvisoryID] =
				fmt.Sprintf("https://alas.aws.amazon.com/%s.html", advisory.AdvisoryID)
		}
		return links
	case "ubuntu":
		links["Ubuntu-CVE"] = "http://people.ubuntu.com/~ubuntu-security/cve/" + v.CveID
		return links
	case "debian":
		links["Debian-CVE"] = "https://security-tracker.debian.org/tracker/" + v.CveID
	case "FreeBSD":
		for _, advisory := range v.DistroAdvisories {
			links["FreeBSD-VuXML"] = fmt.Sprintf("https://vuxml.freebsd.org/freebsd/%s.html", advisory.AdvisoryID)

		}
		return links
	}
	return links
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

// DistroAdvisory has Amazon Linux, RHEL, FreeBSD Security Advisory information.
type DistroAdvisory struct {
	AdvisoryID string
	Severity   string
	Issued     time.Time
	Updated    time.Time
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
