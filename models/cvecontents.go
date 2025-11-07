package models

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/future-architect/vuls/constant"
)

// CveContents has CveContent
type CveContents map[CveContentType][]CveContent

// NewCveContents create CveContents
func NewCveContents(conts ...CveContent) CveContents {
	m := CveContents{}
	for _, cont := range conts {
		switch cont.Type {
		case Jvn:
			if !slices.ContainsFunc(m[cont.Type], func(e CveContent) bool {
				return cont.SourceLink == e.SourceLink
			}) {
				m[cont.Type] = append(m[cont.Type], cont)
			}
		default:
			m[cont.Type] = []CveContent{cont}
		}
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
		if !slices.Contains(exceptCtypes, ctype) {
			values[ctype] = content
		}
	}
	return
}

// PrimarySrcURLs returns link of source
func (v CveContents) PrimarySrcURLs(lang, myFamily, cveID string, confidences Confidences) (values []CveContentStr) {
	if cveID == "" {
		return
	}

	for _, ctype := range append(append(CveContentTypes{Mitre, Nvd, Vulncheck, Jvn}, GetCveContentTypes(myFamily)...), GitHub) {
		for _, cont := range v[ctype] {
			switch ctype {
			case Nvd, Vulncheck:
				for _, r := range cont.References {
					if slices.Contains(r.Tags, "Vendor Advisory") {
						if !slices.ContainsFunc(values, func(e CveContentStr) bool {
							return e.Type == ctype && e.Value == r.Link
						}) {
							values = append(values, CveContentStr{
								Type:  ctype,
								Value: r.Link,
							})
						}
					}
				}
				if cont.SourceLink != "" && !slices.ContainsFunc(values, func(e CveContentStr) bool {
					return e.Type == ctype && e.Value == cont.SourceLink
				}) {
					values = append(values, CveContentStr{
						Type:  ctype,
						Value: cont.SourceLink,
					})
				}
			case Jvn:
				if lang == "ja" || slices.ContainsFunc(confidences, func(e Confidence) bool {
					return e.DetectionMethod == JvnVendorProductMatchStr
				}) {
					if cont.SourceLink != "" && !slices.ContainsFunc(values, func(e CveContentStr) bool {
						return e.Type == ctype && e.Value == cont.SourceLink
					}) {
						values = append(values, CveContentStr{
							Type:  ctype,
							Value: cont.SourceLink,
						})
					}
				}
			default:
				if cont.SourceLink != "" && !slices.ContainsFunc(values, func(e CveContentStr) bool {
					return e.Type == ctype && e.Value == cont.SourceLink
				}) {
					values = append(values, CveContentStr{
						Type:  ctype,
						Value: cont.SourceLink,
					})
				}
			}
		}
	}

	if len(values) == 0 && strings.HasPrefix(cveID, "CVE") {
		return []CveContentStr{{
			Type:  Nvd,
			Value: fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
		}}
	}
	return values
}

// PatchURLs returns link of patch
func (v CveContents) PatchURLs() (urls []string) {
	for _, cont := range v[Nvd] {
		for _, r := range cont.References {
			if slices.Contains(r.Tags, "Patch") && !slices.Contains(urls, r.Link) {
				urls = append(urls, r.Link)
			}
		}
	}
	return
}

// CveContentCpes has CveContentType and Value
type CveContentCpes struct {
	Type  CveContentType
	Value []Cpe
}

// Cpes returns affected CPEs of this Vulnerability
func (v CveContents) Cpes(myFamily string) (values []CveContentCpes) {
	order := GetCveContentTypes(myFamily)
	order = append(order, AllCveContetTypes.Except(order...)...)

	for _, ctype := range order {
		for _, cont := range v[ctype] {
			if len(cont.Cpes) == 0 {
				continue
			}
			if !slices.ContainsFunc(values, func(e CveContentCpes) bool {
				return e.Type == ctype && slices.Equal(e.Value, cont.Cpes)
			}) {
				values = append(values, CveContentCpes{
					Type:  ctype,
					Value: cont.Cpes,
				})
			}
		}
	}
	return
}

// CveContentRefs has CveContentType and References
type CveContentRefs struct {
	Type  CveContentType
	Value []Reference
}

// References returns References
func (v CveContents) References(myFamily string) (values []CveContentRefs) {
	order := GetCveContentTypes(myFamily)
	order = append(order, AllCveContetTypes.Except(order...)...)

	for _, ctype := range order {
		for _, cont := range v[ctype] {
			if len(cont.References) == 0 {
				continue
			}
			if !slices.ContainsFunc(values, func(e CveContentRefs) bool {
				return e.Type == ctype && slices.EqualFunc(e.Value, cont.References, func(e1, e2 Reference) bool {
					return e1.Link == e2.Link && e1.RefID == e2.RefID && e1.Source == e2.Source && slices.Equal(e1.Tags, e2.Tags)
				})
			}) {
				values = append(values, CveContentRefs{
					Type:  ctype,
					Value: cont.References,
				})
			}
		}
	}

	return
}

// CweIDs returns related CweIDs of the vulnerability
func (v CveContents) CweIDs(myFamily string) (values []CveContentStr) {
	order := GetCveContentTypes(myFamily)
	order = append(order, AllCveContetTypes.Except(order...)...)
	for _, ctype := range order {
		for _, cont := range v[ctype] {
			if len(cont.CweIDs) == 0 {
				continue
			}
			for _, cweID := range cont.CweIDs {
				if !slices.ContainsFunc(values, func(e CveContentStr) bool {
					return e.Type == ctype && e.Value == cweID
				}) {
					values = append(values, CveContentStr{
						Type:  ctype,
						Value: cweID,
					})
				}
			}
		}
	}
	return
}

// UniqCweIDs returns Uniq CweIDs
func (v CveContents) UniqCweIDs(myFamily string) []CveContentStr {
	uniq := map[string]CveContentStr{}
	for _, cwes := range v.CweIDs(myFamily) {
		uniq[cwes.Value] = cwes
	}
	return slices.Collect(maps.Values(uniq))
}

// CveContentSSVC has CveContentType and SSVC
type CveContentSSVC struct {
	Type  CveContentType
	Value SSVC
}

// SSVC returns SSVC
func (v CveContents) SSVC() (value []CveContentSSVC) {
	for _, cont := range v[Mitre] {
		if cont.SSVC == nil {
			continue
		}
		t := Mitre
		if s, ok := cont.Optional["source"]; ok {
			t = CveContentType(fmt.Sprintf("%s(%s)", Mitre, s))
		}
		value = append(value, CveContentSSVC{
			Type:  t,
			Value: *cont.SSVC,
		})
	}
	return
}

// Sort elements for integration-testing
func (v CveContents) Sort() {
	for contType, contents := range v {
		// CVSS40 desc, CVSS3 desc, CVSS2 desc, SourceLink asc
		slices.SortFunc(contents, func(a, b CveContent) int {
			return cmp.Or(
				cmp.Compare(b.Cvss40Score, a.Cvss40Score),
				cmp.Compare(b.Cvss3Score, a.Cvss3Score),
				cmp.Compare(b.Cvss2Score, a.Cvss2Score),
				cmp.Compare(a.SourceLink, b.SourceLink),
				cmp.Compare(a.Cvss40Vector, b.Cvss40Vector),
				cmp.Compare(a.Cvss3Vector, b.Cvss3Vector),
				cmp.Compare(a.Cvss2Vector, b.Cvss2Vector),
				cmp.Compare(fmt.Sprintf("%#v", a.Optional), fmt.Sprintf("%#v", b.Optional)),
			)
		})
		for cveID, cont := range contents {
			slices.SortFunc(cont.References, func(a, b Reference) int { return cmp.Compare(a.Link, b.Link) })
			for i := range cont.References {
				slices.Sort(cont.References[i].Tags)
			}
			slices.Sort(cont.CweIDs)
			contents[cveID] = cont
		}
		v[contType] = contents
	}
}

// CveContent has abstraction of various vulnerability information
type CveContent struct {
	Type           CveContentType    `json:"type"`
	CveID          string            `json:"cveID"`
	Title          string            `json:"title"`
	Summary        string            `json:"summary"`
	Cvss2Score     float64           `json:"cvss2Score"`
	Cvss2Vector    string            `json:"cvss2Vector"`
	Cvss2Severity  string            `json:"cvss2Severity"`
	Cvss3Score     float64           `json:"cvss3Score"`
	Cvss3Vector    string            `json:"cvss3Vector"`
	Cvss3Severity  string            `json:"cvss3Severity"`
	Cvss40Score    float64           `json:"cvss40Score"`
	Cvss40Vector   string            `json:"cvss40Vector"`
	Cvss40Severity string            `json:"cvss40Severity"`
	SSVC           *SSVC             `json:"ssvc,omitempty"`
	SourceLink     string            `json:"sourceLink"`
	Cpes           []Cpe             `json:"cpes,omitempty"`
	References     References        `json:"references,omitempty"`
	CweIDs         []string          `json:"cweIDs,omitempty"`
	Published      time.Time         `json:"published"`
	LastModified   time.Time         `json:"lastModified"`
	Optional       map[string]string `json:"optional,omitempty"`
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
	case "mitre":
		return Mitre
	case "nvd":
		return Nvd
	case "vulncheck":
		return Vulncheck
	case "jvn":
		return Jvn
	case "redhat", "centos":
		return RedHat
	case "alma":
		return Alma
	case "rocky":
		return Rocky
	case "fedora":
		return Fedora
	case "oracle":
		return Oracle
	case "ubuntu":
		return Ubuntu
	case "debian", "debian-oval":
		return Debian
	case "redhat_api":
		return RedHatAPI
	case "debian_security_tracker":
		return DebianSecurityTracker
	case "ubuntu_api":
		return UbuntuAPI
	case constant.OpenSUSE, constant.OpenSUSELeap, constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		return SUSE
	case "alpine":
		return Alpine
	case "microsoft":
		return Microsoft
	case "wordpress":
		return WpScan
	case "amazon":
		return Amazon
	case "trivy":
		return Trivy
	case "trivy:nvd":
		return TrivyNVD
	case "trivy:redhat":
		return TrivyRedHat
	case "trivy:redhat-oval":
		return TrivyRedHatOVAL
	case "trivy:debian":
		return TrivyDebian
	case "trivy:ubuntu":
		return TrivyUbuntu
	case "trivy:centos":
		return TrivyCentOS
	case "trivy:rocky":
		return TrivyRocky
	case "trivy:fedora":
		return TrivyFedora
	case "trivy:amazon":
		return TrivyAmazon
	case "trivy:azure":
		return TrivyAzure
	case "trivy:oracle-oval":
		return TrivyOracleOVAL
	case "trivy:suse-cvrf":
		return TrivySuseCVRF
	case "trivy:alpine":
		return TrivyAlpine
	case "trivy:arch-linux":
		return TrivyArchLinux
	case "trivy:alma":
		return TrivyAlma
	case "trivy:cbl-mariner":
		return TrivyCBLMariner
	case "trivy:photon":
		return TrivyPhoton
	case "trivy:coreos":
		return TrivyCoreOS
	case "trivy:ruby-advisory-db":
		return TrivyRubySec
	case "trivy:php-security-advisories":
		return TrivyPhpSecurityAdvisories
	case "trivy:nodejs-security-wg":
		return TrivyNodejsSecurityWg
	case "trivy:ghsa":
		return TrivyGHSA
	case "trivy:glad":
		return TrivyGLAD
	case "trivy:osv":
		return TrivyOSV
	case "trivy:wolfi":
		return TrivyWolfi
	case "trivy:chainguard":
		return TrivyChainguard
	case "trivy:bitnami":
		return TrivyBitnamiVulndb
	case "trivy:k8s":
		return TrivyK8sVulnDB
	case "trivy:govulndb":
		return TrivyGoVulnDB
	case "trivy:aqua":
		return TrivyAqua
	case "trivy:echo":
		return TrivyEcho
	case "trivy:minimos":
		return TrivyMinimOS
	case "trivy:rootio":
		return TrivyRootIO
	case "GitHub":
		return Trivy
	default:
		return Unknown
	}
}

// GetCveContentTypes return CveContentTypes
func GetCveContentTypes(family string) []CveContentType {
	switch family {
	case constant.RedHat, constant.CentOS:
		return []CveContentType{RedHat, RedHatAPI}
	case constant.Alma:
		return []CveContentType{Alma}
	case constant.Rocky:
		return []CveContentType{Rocky}
	case constant.Fedora:
		return []CveContentType{Fedora}
	case constant.Oracle:
		return []CveContentType{Oracle}
	case constant.Amazon:
		return []CveContentType{Amazon}
	case constant.Debian, constant.Raspbian:
		return []CveContentType{Debian, DebianSecurityTracker}
	case constant.Ubuntu:
		return []CveContentType{Ubuntu, UbuntuAPI}
	case constant.OpenSUSE, constant.OpenSUSELeap, constant.SUSEEnterpriseServer, constant.SUSEEnterpriseDesktop:
		return []CveContentType{SUSE}
	case constant.Alpine:
		return []CveContentType{Alpine}
	case constant.Windows:
		return []CveContentType{Microsoft}
	case string(Trivy):
		return []CveContentType{Trivy, TrivyNVD, TrivyRedHat, TrivyRedHatOVAL, TrivyDebian, TrivyUbuntu, TrivyCentOS, TrivyRocky, TrivyFedora, TrivyAmazon, TrivyAzure, TrivyOracleOVAL, TrivySuseCVRF, TrivyAlpine, TrivyArchLinux, TrivyAlma, TrivyCBLMariner, TrivyPhoton, TrivyCoreOS, TrivyRubySec, TrivyPhpSecurityAdvisories, TrivyNodejsSecurityWg, TrivyGHSA, TrivyGLAD, TrivyOSV, TrivyWolfi, TrivyChainguard, TrivyBitnamiVulndb, TrivyK8sVulnDB, TrivyGoVulnDB, TrivyAqua, TrivyEcho, TrivyMinimOS, TrivyRootIO}
	default:
		return nil
	}
}

const (
	// Mitre is Mitre
	Mitre CveContentType = "mitre"

	// Nvd is Nvd JSON
	Nvd CveContentType = "nvd"

	// Vulncheck is Vulncheck
	Vulncheck CveContentType = "vulncheck"

	// Jvn is Jvn
	Jvn CveContentType = "jvn"

	// Fortinet is Fortinet
	Fortinet CveContentType = "fortinet"

	// Paloalto is Paloalto
	Paloalto CveContentType = "paloalto"

	// Cisco is Cisco
	Cisco CveContentType = "cisco"

	// RedHat is RedHat
	RedHat CveContentType = "redhat"

	// RedHatAPI is RedHat
	RedHatAPI CveContentType = "redhat_api"

	// Alma is Alma
	Alma CveContentType = "alma"

	// Rocky is Rocky
	Rocky CveContentType = "rocky"

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

	// Fedora is Fedora Linux
	Fedora CveContentType = "fedora"

	// SUSE is SUSE Linux
	SUSE CveContentType = "suse"

	// Alpine is Alpine Linux
	Alpine CveContentType = "alpine"

	// Microsoft is Microsoft
	Microsoft CveContentType = "microsoft"

	// WpScan is WordPress
	WpScan CveContentType = "wpscan"

	// Trivy is Trivy
	Trivy CveContentType = "trivy"

	// TrivyNVD is TrivyNVD
	TrivyNVD CveContentType = "trivy:nvd"

	// TrivyRedHat is TrivyRedHat
	TrivyRedHat CveContentType = "trivy:redhat"

	// TrivyRedHatOVAL is TrivyRedHatOVAL
	TrivyRedHatOVAL CveContentType = "trivy:redhat-oval"

	// TrivyDebian is TrivyDebian
	TrivyDebian CveContentType = "trivy:debian"

	// TrivyUbuntu is TrivyUbuntu
	TrivyUbuntu CveContentType = "trivy:ubuntu"

	// TrivyCentOS is TrivyCentOS
	TrivyCentOS CveContentType = "trivy:centos"

	// TrivyRocky is TrivyRocky
	TrivyRocky CveContentType = "trivy:rocky"

	// TrivyFedora is TrivyFedora
	TrivyFedora CveContentType = "trivy:fedora"

	// TrivyAmazon is TrivyAmazon
	TrivyAmazon CveContentType = "trivy:amazon"

	// TrivyOracleOVAL is TrivyOracle
	TrivyOracleOVAL CveContentType = "trivy:oracle-oval"

	// TrivySuseCVRF is TrivySuseCVRF
	TrivySuseCVRF CveContentType = "trivy:suse-cvrf"

	// TrivyAlpine is TrivyAlpine
	TrivyAlpine CveContentType = "trivy:alpine"

	// TrivyArchLinux is TrivyArchLinux
	TrivyArchLinux CveContentType = "trivy:arch-linux"

	// TrivyAlma is TrivyAlma
	TrivyAlma CveContentType = "trivy:alma"

	// TrivyAzure is TrivyAzure
	TrivyAzure CveContentType = "trivy:azure"

	// TrivyCBLMariner is TrivyCBLMariner
	TrivyCBLMariner CveContentType = "trivy:cbl-mariner"

	// TrivyPhoton is TrivyPhoton
	TrivyPhoton CveContentType = "trivy:photon"

	// TrivyCoreOS is TrivyCoreOS
	TrivyCoreOS CveContentType = "trivy:coreos"

	// TrivyRubySec is TrivyRubySec
	TrivyRubySec CveContentType = "trivy:ruby-advisory-db"

	// TrivyPhpSecurityAdvisories is TrivyPhpSecurityAdvisories
	TrivyPhpSecurityAdvisories CveContentType = "trivy:php-security-advisories"

	// TrivyNodejsSecurityWg is TrivyNodejsSecurityWg
	TrivyNodejsSecurityWg CveContentType = "trivy:nodejs-security-wg"

	// TrivyGHSA is TrivyGHSA
	TrivyGHSA CveContentType = "trivy:ghsa"

	// TrivyGLAD is TrivyGLAD
	TrivyGLAD CveContentType = "trivy:glad"

	// TrivyOSV is TrivyOSV
	TrivyOSV CveContentType = "trivy:osv"

	// TrivyWolfi is TrivyWolfi
	TrivyWolfi CveContentType = "trivy:wolfi"

	// TrivyChainguard is TrivyChainguard
	TrivyChainguard CveContentType = "trivy:chainguard"

	// TrivyBitnamiVulndb is TrivyBitnamiVulndb
	TrivyBitnamiVulndb CveContentType = "trivy:bitnami"

	// TrivyK8sVulnDB is TrivyK8sVulnDB
	TrivyK8sVulnDB CveContentType = "trivy:k8s"

	// TrivyGoVulnDB is TrivyGoVulnDB
	TrivyGoVulnDB CveContentType = "trivy:govulndb"

	// TrivyAqua is TrivyAqua
	TrivyAqua CveContentType = "trivy:aqua"

	// TrivyEcho is TrivyEcho
	TrivyEcho CveContentType = "trivy:echo"

	// TrivyMinimOS is TrivyMinimOS
	TrivyMinimOS CveContentType = "trivy:minimos"

	// TrivyRootIO is TrivyRootIO
	TrivyRootIO CveContentType = "trivy:rootio"

	// GitHub is GitHub Security Alerts
	GitHub CveContentType = "github"

	// Unknown is Unknown
	Unknown CveContentType = "unknown"
)

// CveContentTypes has slide of CveContentType
type CveContentTypes []CveContentType

// AllCveContetTypes has all of CveContentTypes
var AllCveContetTypes = CveContentTypes{
	Mitre,
	Nvd,
	Vulncheck,
	Jvn,
	Fortinet,
	Paloalto,
	Cisco,
	RedHat,
	RedHatAPI,
	Alma,
	Rocky,
	Debian,
	DebianSecurityTracker,
	Ubuntu,
	UbuntuAPI,
	Amazon,
	Fedora,
	SUSE,
	Alpine,
	Microsoft,
	WpScan,
	Trivy,
	TrivyNVD,
	TrivyRedHat,
	TrivyRedHatOVAL,
	TrivyDebian,
	TrivyUbuntu,
	TrivyCentOS,
	TrivyRocky,
	TrivyFedora,
	TrivyAmazon,
	TrivyAzure,
	TrivyOracleOVAL,
	TrivySuseCVRF,
	TrivyAlpine,
	TrivyArchLinux,
	TrivyAlma,
	TrivyCBLMariner,
	TrivyPhoton,
	TrivyCoreOS,
	TrivyRubySec,
	TrivyPhpSecurityAdvisories,
	TrivyNodejsSecurityWg,
	TrivyGHSA,
	TrivyGLAD,
	TrivyOSV,
	TrivyWolfi,
	TrivyChainguard,
	TrivyBitnamiVulndb,
	TrivyK8sVulnDB,
	TrivyGoVulnDB,
	TrivyAqua,
	TrivyEcho,
	TrivyMinimOS,
	TrivyRootIO,
	GitHub,
}

// Except returns CveContentTypes except for given args
func (c CveContentTypes) Except(excepts ...CveContentType) (excepted CveContentTypes) {
	for _, ctype := range c {
		if !slices.Contains(excepts, ctype) {
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

// SSVC has SSVC decision points
type SSVC struct {
	Exploitation    string `json:"exploitation,omitempty"`
	Automatable     string `json:"automatable,omitempty"`
	TechnicalImpact string `json:"technical_impact,omitempty"`
}
