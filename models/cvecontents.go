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
)

// CveContents has CveContent
type CveContents map[CveContentType]CveContent

// NewCveContents create CveContents
func NewCveContents(conts ...CveContent) CveContents {
	m := CveContents{}
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
	values = CveContents{}
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

// Format CVSS Score and Vector
func (c Cvss2) Format() string {
	return fmt.Sprintf("%3.1f/%s", c.Score, c.Vector)
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
	if 0 < max {
		return value
	}

	// If CVSS score isn't on NVD, RedHat and JVN use OVAL's Severity information.
	// Convert severity to cvss srore, then returns max severity.
	// Only Ubuntu, RedHat and Oracle OVAL has severity data.
	order = []CveContentType{Ubuntu, RedHat, Oracle}
	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.Severity) {
			score := 0.0
			switch cont.Type {
			case Ubuntu:
				score = severityToScoreForUbuntu(cont.Severity)
			case Oracle, RedHat:
				score = severityToScoreForRedHat(cont.Severity)
			}
			if max < score {
				value = CveContentCvss2{
					Type: ctype,
					Value: Cvss2{
						Score:    score,
						Vector:   cont.Cvss2Vector,
						Severity: cont.Severity,
					},
				}
			}
			max = score
		}
	}
	return value
}

// Convert Severity to Score for Ubuntu OVAL
func severityToScoreForUbuntu(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "HIGH":
		return 10.0
	case "MEDIUM":
		return 6.9
	case "LOW":
		return 3.9
	}
	return 0
}

// Convert Severity to Score for RedHat, Oracle OVAL
// https://access.redhat.com/security/updates/classification
// Use the definition of CVSSv3 because the exact definition of severity and score is not described.
func severityToScoreForRedHat(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 10.0
	case "IMPORTANT":
		return 8.9
	case "MODERATE":
		return 6.9
	case "LOW":
		return 3.9
	}
	return 0
}

// CveContentCvss3 has CveContentType and Cvss3
type CveContentCvss3 struct {
	Type  CveContentType
	Value Cvss3
}

// Cvss3 has CVSS v3 Score, Vector and  Severity
type Cvss3 struct {
	Score    float64
	Vector   string
	Severity string
}

// Format CVSS Score and Vector
func (c Cvss3) Format() string {
	return fmt.Sprintf("%3.1f/CVSS:3.0/%s", c.Score, c.Vector)
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

// MaxCvssScore returns max CVSS Score
// If there is no CVSS Score, return Severity as a numerical value.
func (v CveContents) MaxCvssScore() float64 {
	v3Max := v.MaxCvss3Score()
	v2Max := v.MaxCvss2Score()
	max := v3Max.Value.Score
	if max < v2Max.Value.Score {
		max = v2Max.Value.Score
	}
	return max
}

// FormatMaxCvssScore returns Max CVSS Score
func (v CveContents) FormatMaxCvssScore() string {
	v2Max := v.MaxCvss2Score()
	v3Max := v.MaxCvss3Score()
	if v2Max.Value.Score <= v3Max.Value.Score {
		return fmt.Sprintf("%3.1f %s (%s)",
			v3Max.Value.Score,
			strings.ToUpper(v3Max.Value.Severity),
			v3Max.Type)
	}
	return fmt.Sprintf("%3.1f %s (%s)",
		v2Max.Value.Score,
		strings.ToUpper(v2Max.Value.Severity),
		v2Max.Type)
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
			if index < len(summary) {
				summary = summary[0:index] + "..."
			}
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
func (v CveContents) SourceLinks(lang, myFamily, cveID string) (values []CveContentStr) {
	if lang == "ja" {
		if cont, found := v[JVN]; found && 0 < len(cont.SourceLink) {
			values = append(values, CveContentStr{JVN, cont.SourceLink})
		}
	}

	order := CveContentTypes{NVD, NewCveContentType(myFamily)}
	for _, ctype := range order {
		if cont, found := v[ctype]; found {
			values = append(values, CveContentStr{ctype, cont.SourceLink})
		}
	}

	if len(values) == 0 {
		return []CveContentStr{{
			Type:  NVD,
			Value: "https://nvd.nist.gov/vuln/detail/" + cveID,
		}}
	}
	return values
}

// VendorLink returns link of source
func (v CveContents) VendorLink(myFamily string) CveContentStr {
	ctype := NewCveContentType(myFamily)
	if cont, ok := v[ctype]; ok {
		return CveContentStr{ctype, cont.SourceLink}
	}
	return CveContentStr{ctype, ""}
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

// CweIDs returns related CweIDs of the vulnerability
func (v CveContents) CweIDs(myFamily string) (values []CveContentStr) {
	order := CveContentTypes{NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order)...)...)

	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.CweID) {
			// RedHat's OVAL sometimes contains multiple CWE-IDs separated by spaces
			for _, cweID := range strings.Fields(cont.CweID) {
				values = append(values, CveContentStr{
					Type:  ctype,
					Value: cweID,
				})
			}
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

	// Oracle is Oracle Linux
	Oracle CveContentType = "oracle"

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
