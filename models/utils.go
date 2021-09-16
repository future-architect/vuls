//go:build !scanner
// +build !scanner

package models

import (
	"strings"

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

		cweIDs := []string{}
		for _, cid := range nvd.Cwes {
			cweIDs = append(cweIDs, cid.CweID)
		}

		desc := []string{}
		for _, d := range nvd.Descriptions {
			desc = append(desc, d.Value)
		}

		cve := CveContent{
			Type:          Nvd,
			CveID:         cveID,
			Summary:       strings.Join(desc, "\n"),
			Cvss2Score:    nvd.Cvss2.BaseScore,
			Cvss2Vector:   nvd.Cvss2.VectorString,
			Cvss2Severity: nvd.Cvss2.Severity,
			Cvss3Score:    nvd.Cvss3.BaseScore,
			Cvss3Vector:   nvd.Cvss3.VectorString,
			Cvss3Severity: nvd.Cvss3.BaseSeverity,
			SourceLink:    "https://nvd.nist.gov/vuln/detail/" + cveID,
			// Cpes:          cpes,
			CweIDs:       cweIDs,
			References:   refs,
			Published:    nvd.PublishedDate,
			LastModified: nvd.LastModifiedDate,
		}
		cves = append(cves, cve)
	}
	return cves, exploits, mitigations
}
