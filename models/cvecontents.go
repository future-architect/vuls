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

package models

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"
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
		if cont, found := v[Jvn]; found && 0 < len(cont.SourceLink) {
			values = append(values, CveContentStr{Jvn, cont.SourceLink})
		}
	}

	order := CveContentTypes{Nvd, NvdXML, NewCveContentType(myFamily)}
	for _, ctype := range order {
		if cont, found := v[ctype]; found {
			if cont.SourceLink == "" {
				continue
			}
			values = append(values, CveContentStr{ctype, cont.SourceLink})
		}
	}

	if len(values) == 0 {
		return []CveContentStr{{
			Type:  Nvd,
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
	order = append(order, AllCveContetTypes.Except(order...)...)

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
	order = append(order, AllCveContetTypes.Except(order...)...)

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
	order = append(order, AllCveContetTypes.Except(order...)...)
	for _, ctype := range order {
		if cont, found := v[ctype]; found && 0 < len(cont.CweIDs) {
			for _, cweID := range cont.CweIDs {
				for _, val := range values {
					if val.Value == cweID {
						continue
					}
				}
				values = append(values, CveContentStr{
					Type:  ctype,
					Value: cweID,
				})
			}
		}
	}
	return
}

// UniqCweIDs returns Uniq CweIDs
func (v CveContents) UniqCweIDs(myFamily string) (values []CveContentStr) {
	uniq := map[string]CveContentStr{}
	for _, cwes := range v.CweIDs(myFamily) {
		uniq[cwes.Value] = cwes
	}
	for _, cwe := range uniq {
		values = append(values, cwe)
	}
	return values
}

// CveContent has abstraction of various vulnerability information
type CveContent struct {
	Type          CveContentType    `json:"type"`
	CveID         string            `json:"cveID"`
	Title         string            `json:"title"`
	Summary       string            `json:"summary"`
	Cvss2Score    float64           `json:"cvss2Score"`
	Cvss2Vector   string            `json:"cvss2Vector"`
	Cvss2Severity string            `json:"cvss2Severity"`
	Cvss3Score    float64           `json:"cvss3Score"`
	Cvss3Vector   string            `json:"cvss3Vector"`
	Cvss3Severity string            `json:"cvss3Severity"`
	SourceLink    string            `json:"sourceLink"`
	Cpes          []Cpe             `json:"cpes,omitempty"`
	References    References        `json:"references,omitempty"`
	CweIDs        []string          `json:"cweIDs,omitempty"`
	Published     time.Time         `json:"published"`
	LastModified  time.Time         `json:"lastModified"`
	Mitigation    string            `json:"mitigation"` // RedHat API
	Optional      map[string]string `json:"optional,omitempty"`
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
	case "nvdxml":
		return NvdXML
	case "nvd":
		return Nvd
	case "jvn":
		return Jvn
	case "redhat", "centos":
		return RedHat
	case "oracle":
		return Oracle
	case "ubuntu":
		return Ubuntu
	case "debian", vulnerability.DebianOVAL:
		return Debian
	case "redhat_api":
		return RedHatAPI
	case "debian_security_tracker":
		return DebianSecurityTracker
	case "microsoft":
		return Microsoft
	case "wordpress":
		return WPVulnDB
	case "amazon":
		return Amazon
	case vulnerability.NodejsSecurityWg:
		return NodeSec
	case vulnerability.PythonSafetyDB:
		return PythonSec
	case vulnerability.RustSec:
		return RustSec
	case vulnerability.PhpSecurityAdvisories:
		return PhpSec
	case vulnerability.RubySec:
		return RubySec
	default:
		return Unknown
	}
}

const (
	// NvdXML is NvdXML
	NvdXML CveContentType = "nvdxml"

	// Nvd is Nvd
	Nvd CveContentType = "nvd"

	// Jvn is Jvn
	Jvn CveContentType = "jvn"

	// RedHat is RedHat
	RedHat CveContentType = "redhat"

	// RedHatAPI is RedHat
	RedHatAPI CveContentType = "redhat_api"

	// DebianSecurityTracker is Debian Secury tracker
	DebianSecurityTracker CveContentType = "debian_security_tracker"

	// Debian is Debian
	Debian CveContentType = "debian"

	// Ubuntu is Ubuntu
	Ubuntu CveContentType = "ubuntu"

	// Oracle is Oracle Linux
	Oracle CveContentType = "oracle"

	// Amazon is Amazon Linux
	Amazon CveContentType = "amazon"

	// SUSE is SUSE Linux
	SUSE CveContentType = "suse"

	// Microsoft is Microsoft
	Microsoft CveContentType = "microsoft"

	// WPVulnDB is WordPress
	WPVulnDB CveContentType = "wpvulndb"

	// NodeSec : for JS
	NodeSec CveContentType = "node"

	// PythonSec : for PHP
	PythonSec CveContentType = "python"

	// PhpSec : for PHP
	PhpSec CveContentType = "php"

	// RubySec : for Ruby
	RubySec CveContentType = "ruby"

	// RustSec : for Rust
	RustSec CveContentType = "rust"

	// Unknown is Unknown
	Unknown CveContentType = "unknown"
)

// CveContentTypes has slide of CveContentType
type CveContentTypes []CveContentType

// AllCveContetTypes has all of CveContentTypes
var AllCveContetTypes = CveContentTypes{
	Nvd,
	NvdXML,
	Jvn,
	RedHat,
	RedHatAPI,
	Debian,
	Ubuntu,
	Amazon,
	SUSE,
	DebianSecurityTracker,
	WPVulnDB,
	NodeSec,
	PythonSec,
	PhpSec,
	RubySec,
	RustSec,
}

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
	URI             string `json:"uri"`
	FormattedString string `json:"formattedString"`
}

// References is a slice of Reference
type References []Reference

// Reference has a related link of the CVE
type Reference struct {
	Source string `json:"source"`
	Link   string `json:"link"`
	RefID  string `json:"refID"`
}
