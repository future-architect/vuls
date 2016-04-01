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

package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/gosuri/uitable"
)

func toPlainText(scanResult models.ScanResult) (string, error) {
	hostinfo := fmt.Sprintf(
		"%s (%s %s)",
		scanResult.ServerName,
		scanResult.Family,
		scanResult.Release,
	)

	var buffer bytes.Buffer
	for i := 0; i < len(hostinfo); i++ {
		buffer.WriteString("=")
	}
	header := fmt.Sprintf("%s\n%s", hostinfo, buffer.String())

	if len(scanResult.KnownCves) == 0 && len(scanResult.UnknownCves) == 0 {
		return fmt.Sprintf(`
%s
No unsecure packages.
`, header), nil
	}

	summary := ToPlainTextSummary(scanResult)
	scoredReport, unscoredReport := []string{}, []string{}
	scoredReport, unscoredReport = toPlainTextDetails(scanResult, scanResult.Family)

	scored := strings.Join(scoredReport, "\n\n")
	unscored := strings.Join(unscoredReport, "\n\n")
	detail := fmt.Sprintf(`
%s

%s
`,
		scored,
		unscored,
	)
	text := fmt.Sprintf("%s\n%s\n%s\n", header, summary, detail)

	return text, nil
}

// ToPlainTextSummary format summary for plain text.
func ToPlainTextSummary(r models.ScanResult) string {
	stable := uitable.New()
	stable.MaxColWidth = 84
	stable.Wrap = true
	cves := append(r.KnownCves, r.UnknownCves...)
	for _, d := range cves {
		var scols []string

		switch {
		case config.Conf.Lang == "ja" &&
			d.CveDetail.Jvn.ID != 0 &&
			0 < d.CveDetail.CvssScore("ja"):

			summary := d.CveDetail.Jvn.Title
			scols = []string{
				d.CveDetail.CveID,
				fmt.Sprintf("%-4.1f (%s)",
					d.CveDetail.CvssScore(config.Conf.Lang),
					d.CveDetail.Jvn.Severity,
				),
				summary,
			}
		case 0 < d.CveDetail.CvssScore("en"):
			summary := d.CveDetail.Nvd.Summary
			scols = []string{
				d.CveDetail.CveID,
				fmt.Sprintf("%-4.1f",
					d.CveDetail.CvssScore(config.Conf.Lang),
				),
				summary,
			}
		default:
			scols = []string{
				d.CveDetail.CveID,
				"?",
				d.CveDetail.Nvd.Summary,
			}
		}

		cols := make([]interface{}, len(scols))
		for i := range cols {
			cols[i] = scols[i]
		}
		stable.AddRow(cols...)
	}
	return fmt.Sprintf("%s", stable)
}

//TODO Distro Advisory
func toPlainTextDetails(data models.ScanResult, osFamily string) (scoredReport, unscoredReport []string) {
	for _, cve := range data.KnownCves {
		switch config.Conf.Lang {
		case "en":
			if cve.CveDetail.Nvd.ID != 0 {
				scoredReport = append(
					scoredReport, toPlainTextDetailsLangEn(cve, osFamily))
			} else {
				scoredReport = append(
					scoredReport, toPlainTextUnknownCve(cve, osFamily))
			}
		case "ja":
			if cve.CveDetail.Jvn.ID != 0 {
				scoredReport = append(
					scoredReport, toPlainTextDetailsLangJa(cve, osFamily))
			} else if cve.CveDetail.Nvd.ID != 0 {
				scoredReport = append(
					scoredReport, toPlainTextDetailsLangEn(cve, osFamily))
			} else {
				scoredReport = append(
					scoredReport, toPlainTextUnknownCve(cve, osFamily))
			}
		}
	}
	for _, cve := range data.UnknownCves {
		unscoredReport = append(
			unscoredReport, toPlainTextUnknownCve(cve, osFamily))
	}
	return
}

func toPlainTextUnknownCve(cveInfo models.CveInfo, osFamily string) string {
	cveID := cveInfo.CveDetail.CveID
	dtable := uitable.New()
	dtable.MaxColWidth = 100
	dtable.Wrap = true
	dtable.AddRow(cveID)
	dtable.AddRow("-------------")
	dtable.AddRow("Score", "?")
	dtable.AddRow("NVD",
		fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID))
	dtable.AddRow("CVE Details",
		fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))

	dlinks := distroLinks(cveInfo, osFamily)
	for _, link := range dlinks {
		dtable.AddRow(link.title, link.url)
	}

	return fmt.Sprintf("%s", dtable)
}

func toPlainTextDetailsLangJa(cveInfo models.CveInfo, osFamily string) string {

	cveDetail := cveInfo.CveDetail
	cveID := cveDetail.CveID
	jvn := cveDetail.Jvn

	dtable := uitable.New()
	//TODO resize
	dtable.MaxColWidth = 100
	dtable.Wrap = true
	dtable.AddRow(cveID)
	dtable.AddRow("-------------")
	if score := cveDetail.Jvn.CvssScore(); 0 < score {
		dtable.AddRow("Score",
			fmt.Sprintf("%4.1f (%s)",
				cveDetail.Jvn.CvssScore(),
				jvn.Severity,
			))
	} else {
		dtable.AddRow("Score", "?")
	}
	dtable.AddRow("Vector", jvn.Vector)
	dtable.AddRow("Title", jvn.Title)
	dtable.AddRow("Description", jvn.Summary)

	dtable.AddRow("JVN", jvn.Link())
	dtable.AddRow("NVD", fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID))
	dtable.AddRow("MITRE", fmt.Sprintf("%s%s", mitreBaseURL, cveID))
	dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
	dtable.AddRow("CVSS Claculator", cveDetail.CvssV2CalculatorLink("ja"))

	dlinks := distroLinks(cveInfo, osFamily)
	for _, link := range dlinks {
		dtable.AddRow(link.title, link.url)
	}

	dtable = addPackageInfos(dtable, cveInfo.Packages)
	dtable = addCpeNames(dtable, cveInfo.CpeNames)

	return fmt.Sprintf("%s", dtable)
}

func toPlainTextDetailsLangEn(d models.CveInfo, osFamily string) string {
	cveDetail := d.CveDetail
	cveID := cveDetail.CveID
	nvd := cveDetail.Nvd

	dtable := uitable.New()
	//TODO resize
	dtable.MaxColWidth = 100
	dtable.Wrap = true
	dtable.AddRow(cveID)
	dtable.AddRow("-------------")

	if score := cveDetail.Nvd.CvssScore(); 0 < score {
		dtable.AddRow("Score",
			fmt.Sprintf("%4.1f (%s)",
				cveDetail.Nvd.CvssScore(),
				nvd.Severity(),
			))
	} else {
		dtable.AddRow("Score", "?")
	}

	dtable.AddRow("Vector", nvd.CvssVector())
	dtable.AddRow("Summary", nvd.Summary)
	dtable.AddRow("NVD", fmt.Sprintf("%s?vulnId=%s", nvdBaseURL, cveID))
	dtable.AddRow("MITRE", fmt.Sprintf("%s%s", mitreBaseURL, cveID))
	dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
	dtable.AddRow("CVSS Claculator", cveDetail.CvssV2CalculatorLink("en"))

	links := distroLinks(d, osFamily)
	for _, link := range links {
		dtable.AddRow(link.title, link.url)
	}
	dtable = addPackageInfos(dtable, d.Packages)
	dtable = addCpeNames(dtable, d.CpeNames)

	return fmt.Sprintf("%s\n", dtable)
}

type distroLink struct {
	title string
	url   string
}

// addVendorSite add Vendor site of the CVE to table
func distroLinks(cveInfo models.CveInfo, osFamily string) []distroLink {
	cveID := cveInfo.CveDetail.CveID
	switch osFamily {
	case "rhel", "centos":
		links := []distroLink{
			{
				"RHEL-CVE",
				fmt.Sprintf("%s/%s", redhatSecurityBaseURL, cveID),
			},
		}
		for _, advisory := range cveInfo.DistroAdvisories {
			aidURL := strings.Replace(advisory.AdvisoryID, ":", "-", -1)
			links = append(links, distroLink{
				//  "RHEL-errata",
				advisory.AdvisoryID,
				fmt.Sprintf(redhatRHSABaseBaseURL, aidURL),
			})
		}
		return links
	case "amazon":
		links := []distroLink{
			{
				"RHEL-CVE",
				fmt.Sprintf("%s/%s", redhatSecurityBaseURL, cveID),
			},
		}
		for _, advisory := range cveInfo.DistroAdvisories {
			links = append(links, distroLink{
				//  "Amazon-ALAS",
				advisory.AdvisoryID,
				fmt.Sprintf(amazonSecurityBaseURL, advisory.AdvisoryID),
			})
		}
		return links
	case "ubuntu":
		return []distroLink{
			{
				"Ubuntu-CVE",
				fmt.Sprintf("%s/%s", ubuntuSecurityBaseURL, cveID),
			},
			//TODO Ubuntu USN
		}
	case "debian":
		return []distroLink{
			{
				"Debian-CVE",
				fmt.Sprintf("%s/%s", debianTrackerBaseURL, cveID),
			},
			//  TODO Debian dsa
		}
	default:
		return []distroLink{}
	}
}

//TODO
// addPackageInfos add package information related the CVE to table
func addPackageInfos(table *uitable.Table, packs []models.PackageInfo) *uitable.Table {
	for i, p := range packs {
		var title string
		if i == 0 {
			title = "Package/CPE"
		}
		ver := fmt.Sprintf(
			"%s -> %s", p.ToStringCurrentVersion(), p.ToStringNewVersion())
		table.AddRow(title, ver)
	}
	return table
}

func addCpeNames(table *uitable.Table, names []models.CpeName) *uitable.Table {
	for _, p := range names {
		table.AddRow("CPE", fmt.Sprintf("%s", p.Name))
	}
	return table
}
