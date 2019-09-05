package models

import (
	"strings"

	cvedict "github.com/kotakanbe/go-cve-dictionary/models"
)

// ConvertNvdXMLToModel convert NVD to CveContent
func ConvertNvdXMLToModel(cveID string, nvd *cvedict.NvdXML) *CveContent {
	if nvd == nil {
		return nil
	}
	var cpes []Cpe
	for _, c := range nvd.Cpes {
		cpes = append(cpes, Cpe{
			FormattedString: c.FormattedString,
			URI:             c.URI,
		})
	}

	var refs []Reference
	for _, r := range nvd.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	cweIDs := []string{}
	for _, cid := range nvd.Cwes {
		cweIDs = append(cweIDs, cid.CweID)
	}

	return &CveContent{
		Type:          Nvd,
		CveID:         cveID,
		Summary:       nvd.Summary,
		Cvss2Score:    nvd.Cvss2.BaseScore,
		Cvss2Vector:   nvd.Cvss2.VectorString,
		Cvss2Severity: nvd.Cvss2.Severity,
		SourceLink:    "https://nvd.nist.gov/vuln/detail/" + cveID,
		// Cpes:          cpes,
		CweIDs:       cweIDs,
		References:   refs,
		Published:    nvd.PublishedDate,
		LastModified: nvd.LastModifiedDate,
	}
}

// ConvertJvnToModel convert JVN to CveContent
func ConvertJvnToModel(cveID string, jvn *cvedict.Jvn) *CveContent {
	if jvn == nil {
		return nil
	}
	var cpes []Cpe
	for _, c := range jvn.Cpes {
		cpes = append(cpes, Cpe{
			FormattedString: c.FormattedString,
			URI:             c.URI,
		})
	}

	refs := []Reference{}
	for _, r := range jvn.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	return &CveContent{
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
}

// ConvertNvdJSONToModel convert NVD to CveContent
func ConvertNvdJSONToModel(cveID string, nvd *cvedict.NvdJSON) *CveContent {
	if nvd == nil {
		return nil
	}
	var cpes []Cpe
	for _, c := range nvd.Cpes {
		cpes = append(cpes, Cpe{
			FormattedString: c.FormattedString,
			URI:             c.URI,
		})
	}

	var refs []Reference
	for _, r := range nvd.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	cweIDs := []string{}
	for _, cid := range nvd.Cwes {
		cweIDs = append(cweIDs, cid.CweID)
	}

	desc := []string{}
	for _, d := range nvd.Descriptions {
		desc = append(desc, d.Value)
	}

	return &CveContent{
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
}
