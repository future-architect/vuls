package models

import (
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
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

// PrimarySrcURLs returns link of source
func (v CveContents) PrimarySrcURLs(lang, myFamily, cveID string) (values []CveContentStr) {
	if cveID == "" {
		return
	}

	if cont, found := v[Nvd]; found {
		for _, r := range cont.References {
			for _, t := range r.Tags {
				if t == "Vendor Advisory" {
					values = append(values, CveContentStr{Nvd, r.Link})
				}
			}
		}
	}

	order := CveContentTypes{Nvd, NewCveContentType(myFamily), GitHub}
	for _, ctype := range order {
		if cont, found := v[ctype]; found {
			if cont.SourceLink == "" {
				continue
			}
			values = append(values, CveContentStr{ctype, cont.SourceLink})
		}
	}

	if lang == "ja" {
		if cont, found := v[Jvn]; found && 0 < len(cont.SourceLink) {
			values = append(values, CveContentStr{Jvn, cont.SourceLink})
		}
	}

	if len(values) == 0 && strings.HasPrefix(cveID, "CVE") {
		return []CveContentStr{{
			Type:  Nvd,
			Value: "https://nvd.nist.gov/vuln/detail/" + cveID,
		}}
	}
	return values
}

// PatchURLs returns link of patch
func (v CveContents) PatchURLs() (urls []string) {
	cont, found := v[Nvd]
	if !found {
		return
	}
	for _, r := range cont.References {
		for _, t := range r.Tags {
			if t == "Patch" {
				urls = append(urls, r.Link)
			}
		}
	}
	return
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
	case "nvd":
		return Nvd
	case "jvn":
		return Jvn
	case "redhat", "centos", "rocky":
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
	case "ubuntu_api":
		return UbuntuAPI
	case "microsoft":
		return Microsoft
	case "wordpress":
		return WpScan
	case "amazon":
		return Amazon
	case "trivy":
		return Trivy
	case "GitHub":
		return Trivy
	default:
		return Unknown
	}
}

const (
	// Nvd is Nvd JSON
	Nvd CveContentType = "nvd"

	// Jvn is Jvn
	Jvn CveContentType = "jvn"

	// RedHat is RedHat
	RedHat CveContentType = "redhat"

	// RedHatAPI is RedHat
	RedHatAPI CveContentType = "redhat_api"

	// DebianSecurityTracker is Debian Security tracker
	DebianSecurityTracker CveContentType = "debian_security_tracker"

	// Debian is Debian
	Debian CveContentType = "debian"

	// Ubuntu is Ubuntu
	Ubuntu CveContentType = "ubuntu"

	// UbuntuAPI is Ubuntu
	UbuntuAPI CveContentType = "ubuntu_api"

	// Oracle is Oracle Linux
	Oracle CveContentType = "oracle"

	// Amazon is Amazon Linux
	Amazon CveContentType = "amazon"

	// SUSE is SUSE Linux
	SUSE CveContentType = "suse"

	// Microsoft is Microsoft
	Microsoft CveContentType = "microsoft"

	// WpScan is WordPress
	WpScan CveContentType = "wpscan"

	// Trivy is Trivy
	Trivy CveContentType = "trivy"

	// GitHub is GitHub Security Alerts
	GitHub CveContentType = "github"

	// Unknown is Unknown
	Unknown CveContentType = "unknown"
)

// CveContentTypes has slide of CveContentType
type CveContentTypes []CveContentType

// AllCveContetTypes has all of CveContentTypes
var AllCveContetTypes = CveContentTypes{
	Nvd,
	Jvn,
	RedHat,
	RedHatAPI,
	Debian,
	DebianSecurityTracker,
	Ubuntu,
	UbuntuAPI,
	Amazon,
	SUSE,
	WpScan,
	Trivy,
	GitHub,
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
	Link   string   `json:"link,omitempty"`
	Source string   `json:"source,omitempty"`
	RefID  string   `json:"refID,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}
