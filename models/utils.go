//go:build !scanner

package models

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	cvedict "github.com/vulsio/go-cve-dictionary/models"
)

// ConvertJvnToModel convert JVN to CveContent
func ConvertJvnToModel(cveID string, jvns []cvedict.Jvn) []CveContent {
	cves := make([]CveContent, 0, len(jvns))
	for _, jvn := range jvns {
		// cpes := []Cpe{}
		// for _, c := range jvn.Cpes {
		// 	cpes = append(cpes, Cpe{
		// 		FormattedString: c.FormattedString,
		// 		URI:             c.URI,
		// 	})
		// }

		refs := []Reference{}
		for _, r := range jvn.References {
			refs = append(refs, Reference{
				Link:   r.Link,
				Source: r.Source,
			})
		}

		cve := CveContent{
			Type:          Jvn,
			CveID:         cveID,
			Title:         jvn.Title,
			Summary:       jvn.Summary,
			Cvss2Score:    jvn.Cvss2.BaseScore,
			Cvss2Vector:   jvn.Cvss2.VectorString,
			Cvss2Severity: jvn.Cvss2.Severity,
			Cvss3Score:    jvn.Cvss3.BaseScore,
			Cvss3Vector:   jvn.Cvss3.VectorString,
			Cvss3Severity: jvn.Cvss3.BaseSeverity,
			SourceLink:    jvn.JvnLink,
			// Cpes:          cpes,
			References:   refs,
			Published:    jvn.PublishedDate,
			LastModified: jvn.LastModifiedDate,
		}
		cves = append(cves, cve)
	}
	return cves
}

// ConvertEuvdToModel convert EUVD to CveContent
func ConvertEuvdToModel(cveID string, euvds []cvedict.Euvd) []CveContent {
	cves := make([]CveContent, 0, len(euvds))
	for _, euvd := range euvds {
		refs := make([]Reference, 0, len(euvd.References))
		for _, r := range euvd.References {
			refs = append(refs, Reference{
				Link:   r.Link,
				Source: r.Source,
			})
		}

		cve := CveContent{
			Type:         Euvd,
			CveID:        cveID,
			Title:        euvd.EuvdID,
			Summary:      euvd.Description,
			SourceLink:   fmt.Sprintf("https://euvd.enisa.europa.eu/vulnerability/%s", euvd.EuvdID),
			References:   refs,
			Published:    euvd.DatePublished,
			LastModified: euvd.DateUpdated,
		}

		switch euvd.BaseScoreVersion {
		case "2.0":
			cve.Cvss2Score = euvd.BaseScore
			cve.Cvss2Vector = euvd.BaseScoreVector
			switch {
			case euvd.BaseScore >= 7.0:
				cve.Cvss2Severity = "HIGH"
			case euvd.BaseScore >= 4.0:
				cve.Cvss2Severity = "MEDIUM"
			default:
				cve.Cvss2Severity = "LOW"
			}
		case "3.0", "3.1":
			cve.Cvss3Score = euvd.BaseScore
			cve.Cvss3Vector = euvd.BaseScoreVector
			switch {
			case euvd.BaseScore >= 9.0:
				cve.Cvss3Severity = "CRITICAL"
			case euvd.BaseScore >= 7.0:
				cve.Cvss3Severity = "HIGH"
			case euvd.BaseScore >= 4.0:
				cve.Cvss3Severity = "MEDIUM"
			case euvd.BaseScore >= 0.1:
				cve.Cvss3Severity = "LOW"
			default:
				cve.Cvss3Severity = "NONE"
			}
		case "4.0":
			cve.Cvss40Score = euvd.BaseScore
			cve.Cvss40Vector = euvd.BaseScoreVector
			switch {
			case euvd.BaseScore >= 9.0:
				cve.Cvss40Severity = "CRITICAL"
			case euvd.BaseScore >= 7.0:
				cve.Cvss40Severity = "HIGH"
			case euvd.BaseScore >= 4.0:
				cve.Cvss40Severity = "MEDIUM"
			case euvd.BaseScore >= 0.1:
				cve.Cvss40Severity = "LOW"
			default:
				cve.Cvss40Severity = "NONE"
			}
		default:
		}

		cves = append(cves, cve)
	}
	return cves
}

// ConvertNvdToModel convert NVD to CveContent
func ConvertNvdToModel(cveID string, nvds []cvedict.Nvd) ([]CveContent, []Exploit, []Mitigation) {
	var cves []CveContent //nolint:prealloc
	var refs []Reference
	var exploits []Exploit
	var mitigations []Mitigation
	for _, nvd := range nvds {
		// cpes := []Cpe{}
		// for _, c := range nvd.Cpes {
		// 	cpes = append(cpes, Cpe{
		// 		FormattedString: c.FormattedString,
		// 		URI:             c.URI,
		// 	})
		// }

		for _, r := range nvd.References {
			var tags []string
			if 0 < len(r.Tags) {
				tags = strings.Split(r.Tags, ",")
			}
			refs = append(refs, Reference{
				Link:   r.Link,
				Source: r.Source,
				Tags:   tags,
			})
			if strings.Contains(r.Tags, "Exploit") {
				exploits = append(exploits, Exploit{
					//TODO Add const to here
					// https://github.com/vulsio/go-exploitdb/blob/master/models/exploit.go#L13-L18
					ExploitType: "nvd",
					URL:         r.Link,
				})
			}
			if strings.Contains(r.Tags, "Mitigation") {
				mitigations = append(mitigations, Mitigation{
					CveContentType: Nvd,
					URL:            r.Link,
				})
			}
		}

		desc := make([]string, 0, len(nvd.Descriptions))
		for _, d := range nvd.Descriptions {
			desc = append(desc, d.Value)
		}

		m := map[string]CveContent{}
		for _, cwe := range nvd.Cwes {
			c := m[cwe.Source]
			c.CweIDs = append(c.CweIDs, cwe.CweID)
			m[cwe.Source] = c
		}
		for _, cvss2 := range nvd.Cvss2 {
			c := m[cvss2.Source]
			c.Cvss2Score = cvss2.BaseScore
			c.Cvss2Vector = cvss2.VectorString
			c.Cvss2Severity = cvss2.Severity
			m[cvss2.Source] = c
		}
		for _, cvss3 := range nvd.Cvss3 {
			c := m[cvss3.Source]
			c.Cvss3Score = cvss3.BaseScore
			c.Cvss3Vector = cvss3.VectorString
			c.Cvss3Severity = cvss3.BaseSeverity
			m[cvss3.Source] = c
		}
		for _, cvss40 := range nvd.Cvss40 {
			c := m[cvss40.Source]
			c.Cvss40Score = cvss40.BaseScore
			c.Cvss40Vector = cvss40.VectorString
			c.Cvss40Severity = cvss40.BaseSeverity
			m[cvss40.Source] = c
		}

		for source, cont := range m {
			cves = append(cves, CveContent{
				Type:           Nvd,
				CveID:          cveID,
				Summary:        strings.Join(desc, "\n"),
				Cvss2Score:     cont.Cvss2Score,
				Cvss2Vector:    cont.Cvss2Vector,
				Cvss2Severity:  cont.Cvss2Severity,
				Cvss3Score:     cont.Cvss3Score,
				Cvss3Vector:    cont.Cvss3Vector,
				Cvss3Severity:  cont.Cvss3Severity,
				Cvss40Score:    cont.Cvss40Score,
				Cvss40Vector:   cont.Cvss40Vector,
				Cvss40Severity: cont.Cvss40Severity,
				SourceLink:     fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID),
				// Cpes:          cpes,
				CweIDs:       cont.CweIDs,
				References:   refs,
				Published:    nvd.PublishedDate,
				LastModified: nvd.LastModifiedDate,
				Optional:     map[string]string{"source": source},
			})
		}
	}
	return cves, exploits, mitigations
}

// ConvertVulncheckToModel convert VulnCheck to CveContent
func ConvertVulncheckToModel(cveID string, vulnchecks []cvedict.Vulncheck) []CveContent {
	var cves []CveContent //nolint:prealloc
	for _, vulncheck := range vulnchecks {
		desc := func() string {
			switch i := slices.IndexFunc(vulncheck.Descriptions, func(e cvedict.VulncheckDescription) bool {
				return e.Lang == "en"
			}); i {
			case -1:
				if len(vulncheck.Descriptions) > 0 {
					return vulncheck.Descriptions[0].Value
				}
				return ""
			default:
				return vulncheck.Descriptions[i].Value
			}
		}()

		refs := func() []Reference {
			rs := make([]Reference, 0, len(vulncheck.References))
			for _, r := range vulncheck.References {
				rs = append(rs, Reference{
					Link:   r.Link,
					Source: r.Source,
					Tags: func() []string {
						if r.Tags == "" {
							return nil
						}
						return strings.Split(r.Tags, ",")
					}(),
				})
			}
			return rs
		}()

		m := make(map[string]CveContent)
		for _, cwe := range vulncheck.Cwes {
			c := m[cwe.Source]
			c.CweIDs = append(c.CweIDs, cwe.CweID)
			m[cwe.Source] = c
		}
		for _, cvss2 := range vulncheck.Cvss2 {
			c := m[cvss2.Source]
			c.Cvss2Score = cvss2.BaseScore
			c.Cvss2Vector = cvss2.VectorString
			c.Cvss2Severity = cvss2.Severity
			m[cvss2.Source] = c
		}
		for _, cvss3 := range vulncheck.Cvss3 {
			c := m[cvss3.Source]
			c.Cvss3Score = cvss3.BaseScore
			c.Cvss3Vector = cvss3.VectorString
			c.Cvss3Severity = cvss3.BaseSeverity
			m[cvss3.Source] = c
		}
		for _, cvss40 := range vulncheck.Cvss40 {
			c := m[cvss40.Source]
			c.Cvss40Score = cvss40.BaseScore
			c.Cvss40Vector = cvss40.VectorString
			c.Cvss40Severity = cvss40.BaseSeverity
			m[cvss40.Source] = c
		}

		for source, cont := range m {
			cves = append(cves, CveContent{
				Type:           Vulncheck,
				CveID:          cveID,
				Summary:        desc,
				Cvss2Score:     cont.Cvss2Score,
				Cvss2Vector:    cont.Cvss2Vector,
				Cvss2Severity:  cont.Cvss2Severity,
				Cvss3Score:     cont.Cvss3Score,
				Cvss3Vector:    cont.Cvss3Vector,
				Cvss3Severity:  cont.Cvss3Severity,
				Cvss40Score:    cont.Cvss40Score,
				Cvss40Vector:   cont.Cvss40Vector,
				Cvss40Severity: cont.Cvss40Severity,
				SourceLink:     fmt.Sprintf("https://console.vulncheck.com/cve/%s", cveID),
				CweIDs:         cont.CweIDs,
				References:     refs,
				Published:      vulncheck.PublishedDate,
				LastModified:   vulncheck.LastModifiedDate,
				Optional:       map[string]string{"source": source},
			})
		}
	}
	return cves
}

// ConvertFortinetToModel convert Fortinet to CveContent
func ConvertFortinetToModel(cveID string, fortinets []cvedict.Fortinet) []CveContent {
	cves := make([]CveContent, 0, len(fortinets))
	for _, fortinet := range fortinets {
		refs := make([]Reference, 0, len(fortinet.References))
		for _, r := range fortinet.References {
			refs = append(refs, Reference{
				Link:   r.Link,
				Source: r.Source,
			})
		}

		cweIDs := make([]string, 0, len(fortinet.Cwes))
		for _, cid := range fortinet.Cwes {
			cweIDs = append(cweIDs, cid.CweID)
		}

		cve := CveContent{
			Type:         Fortinet,
			CveID:        cveID,
			Title:        fortinet.Title,
			Summary:      fortinet.Summary,
			Cvss3Score:   fortinet.Cvss3.BaseScore,
			Cvss3Vector:  fortinet.Cvss3.VectorString,
			SourceLink:   fortinet.AdvisoryURL,
			CweIDs:       cweIDs,
			References:   refs,
			Published:    fortinet.PublishedDate,
			LastModified: fortinet.LastModifiedDate,
		}
		cves = append(cves, cve)
	}
	return cves
}

// ConvertMitreToModel convert Mitre to CveContent
func ConvertMitreToModel(cveID string, mitres []cvedict.Mitre) []CveContent {
	var cves []CveContent
	for _, mitre := range mitres {
		for _, c := range mitre.Containers {
			cve := CveContent{
				Type:  Mitre,
				CveID: cveID,
				Title: func() string {
					if c.Title != nil {
						return *c.Title
					}
					return ""
				}(),
				Summary: func() string {
					for _, d := range c.Descriptions {
						if d.Lang == "en" {
							return d.Value
						}
					}
					return ""
				}(),
				SourceLink: fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", cveID),
				Published: func() time.Time {
					if mitre.CVEMetadata.DatePublished != nil {
						return *mitre.CVEMetadata.DatePublished
					}
					return time.Time{}
				}(),
				LastModified: func() time.Time {
					if mitre.CVEMetadata.DateUpdated != nil {
						return *mitre.CVEMetadata.DateUpdated
					}
					if mitre.CVEMetadata.DatePublished != nil {
						return *mitre.CVEMetadata.DatePublished
					}
					return time.Time{}
				}(),
				Optional: map[string]string{"source": func() string {
					if c.ProviderMetadata.ShortName != nil {
						return fmt.Sprintf("%s:%s", c.ContainerType, *c.ProviderMetadata.ShortName)
					}
					return fmt.Sprintf("%s:%s", c.ContainerType, c.ProviderMetadata.OrgID)
				}()},
			}

			for _, m := range c.Metrics {
				if m.CVSSv2 != nil {
					cve.Cvss2Score = m.CVSSv2.BaseScore
					cve.Cvss2Vector = m.CVSSv2.VectorString
				}
				if m.CVSSv30 != nil {
					if cve.Cvss3Vector == "" {
						cve.Cvss3Score = m.CVSSv30.BaseScore
						cve.Cvss3Vector = m.CVSSv30.VectorString
						cve.Cvss3Severity = m.CVSSv30.BaseSeverity
					}
				}
				if m.CVSSv31 != nil {
					cve.Cvss3Score = m.CVSSv31.BaseScore
					cve.Cvss3Vector = m.CVSSv31.VectorString
					cve.Cvss3Severity = m.CVSSv31.BaseSeverity
				}
				if m.CVSSv40 != nil {
					cve.Cvss40Score = m.CVSSv40.BaseScore
					cve.Cvss40Vector = m.CVSSv40.VectorString
					cve.Cvss40Severity = m.CVSSv40.BaseSeverity
				}
				if m.SSVC != nil {
					cve.SSVC = &SSVC{
						Exploitation: func() string {
							if m.SSVC.Exploitation != nil {
								return *m.SSVC.Exploitation
							}
							return ""
						}(),
						Automatable: func() string {
							if m.SSVC.Automatable != nil {
								return *m.SSVC.Automatable
							}
							return ""
						}(),
						TechnicalImpact: func() string {
							if m.SSVC.TechnicalImpact != nil {
								return *m.SSVC.TechnicalImpact
							}
							return ""
						}(),
					}
				}
			}

			for _, r := range c.References {
				cve.References = append(cve.References, Reference{
					Link:   r.Link,
					Source: r.Source,
					Tags: func() []string {
						if len(r.Tags) > 0 {
							return strings.Split(r.Tags, ",")
						}
						return nil
					}(),
				})
			}

			for _, p := range c.ProblemTypes {
				for _, d := range p.Descriptions {
					if d.CweID != nil {
						cve.CweIDs = append(cve.CweIDs, *d.CweID)
					}
				}
			}

			cves = append(cves, cve)
		}
	}
	return cves
}

// ConvertPaloaltoToModel convert Paloalto to CveContent
func ConvertPaloaltoToModel(cveID string, paloaltos []cvedict.Paloalto) []CveContent {
	cves := make([]CveContent, 0, len(paloaltos))
	for _, paloalto := range paloaltos {
		cvss3score, cvss3vector, cvss3severity := func() (float64, string, string) {
			if len(paloalto.CVSSv3) == 0 {
				return 0, "", ""
			}
			v3max := slices.MaxFunc(paloalto.CVSSv3, func(a, b cvedict.PaloaltoCVSS3) int {
				switch {
				case strings.HasPrefix(a.VectorString, "CVSS:3.0/") && strings.HasPrefix(b.VectorString, "CVSS:3.1/"):
					return -1
				case strings.HasPrefix(a.VectorString, "CVSS:3.1/") && strings.HasPrefix(b.VectorString, "CVSS:3.0/"):
					return +1
				default:
					return cmp.Compare(a.BaseScore, b.BaseScore)
				}
			})
			return v3max.BaseScore, v3max.VectorString, v3max.BaseSeverity
		}()
		cvss40score, cvss40vector, cvss40severity := func() (float64, string, string) {
			if len(paloalto.CVSSv40) == 0 {
				return 0, "", ""
			}
			v40max := slices.MaxFunc(paloalto.CVSSv40, func(a, b cvedict.PaloaltoCVSS40) int {
				return cmp.Compare(a.BaseScore, b.BaseScore)
			})
			return v40max.BaseScore, v40max.VectorString, v40max.BaseSeverity
		}()

		cves = append(cves, CveContent{
			Type:  Paloalto,
			CveID: cveID,
			Title: paloalto.Title,
			Summary: func() string {
				for _, d := range paloalto.Descriptions {
					return d.Description
				}
				return ""
			}(),
			Cvss3Score:     cvss3score,
			Cvss3Vector:    cvss3vector,
			Cvss3Severity:  cvss3severity,
			Cvss40Score:    cvss40score,
			Cvss40Vector:   cvss40vector,
			Cvss40Severity: cvss40severity,
			SourceLink: func() string {
				if strings.HasPrefix(paloalto.AdvisoryID, "PAN-CVE-") {
					return fmt.Sprintf("https://security.paloaltonetworks.com/%s", strings.TrimPrefix(paloalto.AdvisoryID, "PAN-"))
				}
				return fmt.Sprintf("https://security.paloaltonetworks.com/%s", paloalto.AdvisoryID)
			}(),
			References: func() []Reference {
				refs := make([]Reference, 0, len(paloalto.References))
				for _, r := range paloalto.References {
					refs = append(refs, Reference{
						Link:   r.Link,
						Source: r.Source,
						Tags: func() []string {
							if len(r.Tags) > 0 {
								return strings.Split(r.Tags, ",")
							}
							return nil
						}(),
					})
				}
				return refs
			}(),
			CweIDs: func() []string {
				cweIDs := make([]string, 0, len(paloalto.ProblemTypes))
				for _, pt := range paloalto.ProblemTypes {
					cweIDs = append(cweIDs, pt.CweID)
				}
				return cweIDs
			}(),
			Published: func() time.Time {
				if paloalto.DatePublic != nil {
					return *paloalto.DatePublic
				}
				return time.Time{}
			}(),
			LastModified: func() time.Time {
				if paloalto.DatePublic != nil {
					return *paloalto.DatePublic
				}
				return time.Time{}
			}(),
		})
	}
	return cves
}

// ConvertCiscoToModel convert Cisco to CveContent
func ConvertCiscoToModel(cveID string, ciscos []cvedict.Cisco) []CveContent {
	cves := make([]CveContent, 0, len(ciscos))
	for _, cisco := range ciscos {
		cves = append(cves, CveContent{
			Type:       Cisco,
			CveID:      cveID,
			Title:      cisco.Title,
			Summary:    cisco.Summary,
			SourceLink: fmt.Sprintf("https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/%s", cisco.AdvisoryID),
			References: func() []Reference {
				refs := make([]Reference, 0, len(cisco.References))
				for _, r := range cisco.References {
					refs = append(refs, Reference{
						Link:   r.Link,
						Source: r.Source,
						Tags: func() []string {
							if len(r.Tags) > 0 {
								return strings.Split(r.Tags, ",")
							}
							return nil
						}(),
					})
				}
				return refs
			}(),
			CweIDs: func() []string {
				cweIDs := make([]string, 0, len(cisco.CweIDs))
				for _, c := range cisco.CweIDs {
					cweIDs = append(cweIDs, c.CweID)
				}
				return cweIDs
			}(),
			Published:    cisco.FirstPublished,
			LastModified: cisco.LastUpdated,
		})
	}
	return cves
}
