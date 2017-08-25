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

	cvedict "github.com/kotakanbe/go-cve-dictionary/models"
)

// ConvertNvdToModel convert NVD to CveContent
func ConvertNvdToModel(cveID string, nvd cvedict.Nvd) *CveContent {
	var cpes []Cpe
	for _, c := range nvd.Cpes {
		cpes = append(cpes, Cpe{CpeName: c.CpeName})
	}

	var refs []Reference
	for _, r := range nvd.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	validVec := true
	for _, v := range []string{
		nvd.AccessVector,
		nvd.AccessComplexity,
		nvd.Authentication,
		nvd.ConfidentialityImpact,
		nvd.IntegrityImpact,
		nvd.AvailabilityImpact,
	} {
		if len(v) == 0 {
			validVec = false
		}
	}

	vector := ""
	if validVec {
		vector = fmt.Sprintf("AV:%s/AC:%s/Au:%s/C:%s/I:%s/A:%s",
			string(nvd.AccessVector[0]),
			string(nvd.AccessComplexity[0]),
			string(nvd.Authentication[0]),
			string(nvd.ConfidentialityImpact[0]),
			string(nvd.IntegrityImpact[0]),
			string(nvd.AvailabilityImpact[0]))
	}

	//TODO CVSSv3
	return &CveContent{
		Type:         NVD,
		CveID:        cveID,
		Summary:      nvd.Summary,
		Cvss2Score:   nvd.Score,
		Cvss2Vector:  vector,
		Severity:     "", // severity is not contained in NVD
		SourceLink:   "https://nvd.nist.gov/vuln/detail/" + cveID,
		Cpes:         cpes,
		CweID:        nvd.CweID,
		References:   refs,
		Published:    nvd.PublishedDate,
		LastModified: nvd.LastModifiedDate,
	}
}

// ConvertJvnToModel convert JVN to CveContent
func ConvertJvnToModel(cveID string, jvn cvedict.Jvn) *CveContent {
	var cpes []Cpe
	for _, c := range jvn.Cpes {
		cpes = append(cpes, Cpe{CpeName: c.CpeName})
	}

	refs := []Reference{}
	for _, r := range jvn.References {
		refs = append(refs, Reference{
			Link:   r.Link,
			Source: r.Source,
		})
	}

	vector := strings.TrimSuffix(strings.TrimPrefix(jvn.Vector, "("), ")")
	return &CveContent{
		Type:         JVN,
		CveID:        cveID,
		Title:        jvn.Title,
		Summary:      jvn.Summary,
		Severity:     jvn.Severity,
		Cvss2Score:   jvn.Score,
		Cvss2Vector:  vector,
		SourceLink:   jvn.JvnLink,
		Cpes:         cpes,
		References:   refs,
		Published:    jvn.PublishedDate,
		LastModified: jvn.LastModifiedDate,
	}
}
