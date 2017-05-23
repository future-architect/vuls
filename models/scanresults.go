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
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	cvedict "github.com/kotakanbe/go-cve-dictionary/models"
)

// ScanResults is a slide of ScanResult
type ScanResults []ScanResult

// ScanResult has the result of scanned CVE information.
type ScanResult struct {
	ScannedAt   time.Time
	JSONVersion string
	Lang        string
	ServerName  string // TOML Section key
	Family      string
	Release     string
	Container   Container
	Platform    Platform

	// Scanned Vulns by SSH scan + CPE + OVAL
	ScannedCves VulnInfos

	Packages Packages
	Errors   []string
	Optional [][]interface{}
}

// ConvertNvdToModel convert NVD to CveContent
func (r ScanResult) ConvertNvdToModel(cveID string, nvd cvedict.Nvd) *CveContent {
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
func (r ScanResult) ConvertJvnToModel(cveID string, jvn cvedict.Jvn) *CveContent {
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

// FilterByCvssOver is filter function.
func (r ScanResult) FilterByCvssOver(over float64) ScanResult {
	filtered := r.ScannedCves.Find(func(v VulnInfo) bool {
		v2Max := v.CveContents.MaxCvss2Score()
		v3Max := v.CveContents.MaxCvss3Score()
		max := v2Max.Value.Score
		if max < v3Max.Value.Score {
			max = v3Max.Value.Score
		}
		if over <= max {
			return true
		}
		return false
	})

	copiedScanResult := r
	copiedScanResult.ScannedCves = filtered
	return copiedScanResult
}

// ReportFileName returns the filename on localhost without extention
func (r ScanResult) ReportFileName() (name string) {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s", r.ServerName)
	}
	return fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
}

// ReportKeyName returns the name of key on S3, Azure-Blob without extention
func (r ScanResult) ReportKeyName() (name string) {
	timestr := r.ScannedAt.Format(time.RFC3339)
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s/%s", timestr, r.ServerName)
	}
	return fmt.Sprintf("%s/%s@%s", timestr, r.Container.Name, r.ServerName)
}

// ServerInfo returns server name one line
func (r ScanResult) ServerInfo() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
	}
	return fmt.Sprintf(
		"%s / %s (%s%s) on %s",
		r.Container.Name,
		r.Container.ContainerID,
		r.Family,
		r.Release,
		r.ServerName,
	)
}

// ServerInfoTui returns server infromation for TUI sidebar
func (r ScanResult) ServerInfoTui() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
	}
	return fmt.Sprintf(
		"|-- %s (%s%s)",
		r.Container.Name,
		r.Family,
		r.Release,
		//  r.Container.ContainerID,
	)
}

// FormatServerName returns server and container name
func (r ScanResult) FormatServerName() string {
	if len(r.Container.ContainerID) == 0 {
		return r.ServerName
	}
	return fmt.Sprintf("%s@%s",
		r.Container.Name, r.ServerName)
}

// CveSummary summarize the number of CVEs group by CVSSv2 Severity
func (r ScanResult) CveSummary() string {
	var high, medium, low, unknown int
	for _, vInfo := range r.ScannedCves {
		score := vInfo.CveContents.MaxCvss2Score().Value.Score
		if score < 0.1 {
			score = vInfo.CveContents.MaxCvss3Score().Value.Score
		}
		switch {
		case 7.0 <= score:
			high++
		case 4.0 <= score:
			medium++
		case 0 < score:
			low++
		default:
			unknown++
		}
	}

	if config.Conf.IgnoreUnscoredCves {
		return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d)",
			high+medium+low, high, medium, low)
	}
	return fmt.Sprintf("Total: %d (High:%d Medium:%d Low:%d ?:%d)",
		high+medium+low+unknown, high, medium, low, unknown)
}

// FormatTextReportHeadedr returns header of text report
func (r ScanResult) FormatTextReportHeadedr() string {
	serverInfo := r.ServerInfo()
	var buf bytes.Buffer
	for i := 0; i < len(serverInfo); i++ {
		buf.WriteString("=")
	}
	return fmt.Sprintf("%s\n%s\n%s\t%s\n",
		r.ServerInfo(),
		buf.String(),
		r.CveSummary(),
		r.Packages.FormatUpdatablePacksSummary(),
	)
}

// Container has Container information
type Container struct {
	ContainerID string
	Name        string
	Image       string
	Type        string
}

// Platform has platform information
type Platform struct {
	Name       string // aws or azure or gcp or other...
	InstanceID string
}
