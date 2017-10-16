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

/*
// Severities returns Severities
func (v CveContents) Severities(myFamily string) (values []CveContentStr) {
	order := CveContentTypes{NVD, NewCveContentType(myFamily)}
	order = append(order, AllCveContetTypes.Except(append(order)...)...)

	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.Severity) {
			values = append(values, CveContentStr{
				Type:  ctype,
				Value: cont.Severity,
			})
		}
	}
	return
}
*/

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
	case "oracle":
		return Oracle
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

	// SUSE is SUSE Linux
	SUSE CveContentType = "suse"

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

// Reference has a related link of the CVE
type Reference struct {
	Source string
	Link   string
	RefID  string
}
