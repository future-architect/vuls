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
	"time"
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

// FindScoredVulns return socred vulnerabilities
func (v VulnInfos) FindScoredVulns() VulnInfos {
	return v.Find(func(vv VulnInfo) bool {
		if 0 < vv.CveContents.MaxCvss2Score().Value.Score ||
			0 < vv.CveContents.MaxCvss3Score().Value.Score {
			return true
		}
		return false
	})
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
