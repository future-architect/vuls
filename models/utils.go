//go:build !scanner

package models

import (
	"fmt"
	"strings"
	"time"

	cvedict "github.com/vulsio/go-cve-dictionary/models"
)

// ConvertJvnToModel convert JVN to CveContent
func ConvertJvnToModel(cveID string, jvns []cvedict.Jvn) []CveContent {
	cves := []CveContent{}
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

// ConvertNvdToModel convert NVD to CveContent
func ConvertNvdToModel(cveID string, nvds []cvedict.Nvd) ([]CveContent, []Exploit, []Mitigation) {
	cves := []CveContent{}
	refs := []Reference{}
	exploits := []Exploit{}
	mitigations := []Mitigation{}
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

		desc := []string{}
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

// ConvertFortinetToModel convert Fortinet to CveContent
func ConvertFortinetToModel(cveID string, fortinets []cvedict.Fortinet) []CveContent {
	cves := []CveContent{}
	for _, fortinet := range fortinets {

		refs := []Reference{}
		for _, r := range fortinet.References {
			refs = append(refs, Reference{
				Link:   r.Link,
				Source: r.Source,
			})
		}

		cweIDs := []string{}
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
