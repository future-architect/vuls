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
	"github.com/k0kubun/pp"
)

const maxColWidth = 80

func formatScanSummary(rs ...models.ScanResult) string {
	table := uitable.New()
	table.MaxColWidth = maxColWidth
	table.Wrap = true
	for _, r := range rs {
		var cols []interface{}
		if len(r.Errors) == 0 {
			cols = []interface{}{
				r.FormatServerName(),
				fmt.Sprintf("%s%s", r.Family, r.Release),
				fmt.Sprintf("%d CVEs", len(r.ScannedCves)),
				r.Packages.FormatUpdatablePacksSummary(),
			}
		} else {
			cols = []interface{}{
				r.FormatServerName(),
				"Error",
				"",
				"Run with --debug to view the details",
			}
		}
		table.AddRow(cols...)
	}
	return fmt.Sprintf("%s\n", table)
}

func formatOneLineSummary(rs ...models.ScanResult) string {
	table := uitable.New()
	table.MaxColWidth = maxColWidth
	table.Wrap = true
	for _, r := range rs {
		var cols []interface{}
		if len(r.Errors) == 0 {
			cols = []interface{}{
				r.FormatServerName(),
				r.CveSummary(),
				r.Packages.FormatUpdatablePacksSummary(),
			}
		} else {
			cols = []interface{}{
				r.FormatServerName(),
				"Error: Scan with --debug to view the details",
				"",
			}
		}
		table.AddRow(cols...)
	}
	return fmt.Sprintf("%s\n", table)
}

func formatShortPlainText(r models.ScanResult) string {
	stable := uitable.New()
	stable.MaxColWidth = maxColWidth
	stable.Wrap = true

	vulns := r.ScannedCves
	if !config.Conf.IgnoreUnscoredCves {
		//TODO Refactoring
		vulns = r.ScannedCves.Find(func(v models.VulnInfo) bool {
			if 0 < v.CveContents.CvssV2Score() || 0 < v.CveContents.CvssV3Score() {
				return true
			}
			return false
		})
	}
	pp.Println(vulns)

	var buf bytes.Buffer
	for i := 0; i < len(r.ServerInfo()); i++ {
		buf.WriteString("=")
	}
	header := fmt.Sprintf("%s\n%s\n%s\t%s\n\n",
		r.ServerInfo(),
		buf.String(),
		r.CveSummary(),
		r.Packages.FormatUpdatablePacksSummary(),
	)

	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Scan with --debug to view the details\n%s\n\n",
			header, r.Errors)
	}

	//TODO
	//      if len(cves) == 0 {
	//          return fmt.Sprintf(`
	//  %s
	//  No CVE-IDs are found in updatable packages.
	//  %s
	//  `, header, r.Packages.FormatUpdatablePacksSummary())
	//      }

	//      for _, d := range cves {
	//          var packsVer string
	//          for _, p := range d.Packages {
	//              packsVer += fmt.Sprintf(
	//                  "%s -> %s\n", p.FormatCurrentVer(), p.FormatNewVer())
	//          }
	//          for _, n := range d.CpeNames {
	//              packsVer += n
	//          }

	//          var scols []string
	//          switch {
	//          //  case config.Conf.Lang == "ja" &&
	//          //TODO
	//          //  0 < d.CveDetail.Jvn.CvssScore():
	//          //  summary := fmt.Sprintf("%s\n%s\n%s\n%sConfidence: %v",
	//          //      d.CveDetail.Jvn.CveTitle(),
	//          //      d.CveDetail.Jvn.Link(),
	//          //      distroLinks(d, r.Family)[0].url,
	//          //      packsVer,
	//          //      d.VulnInfo.Confidence,
	//          //  )
	//          //  scols = []string{
	//          //      d.CveDetail.CveID,
	//          //      fmt.Sprintf("%-4.1f (%s)",
	//          //          d.CveDetail.CvssScore(config.Conf.Lang),
	//          //          d.CveDetail.Jvn.CvssSeverity(),
	//          //      ),
	//          //      summary,
	//          //  }

	//          case 0 < d.CvssV2Score():
	//              var nvd *models.CveContent
	//              if cont, found := d.Get(models.NVD); found {
	//                  nvd = cont
	//              }
	//              summary := fmt.Sprintf("%s\n%s/%s\n%s\n%sConfidence: %v",
	//                  nvd.Summary,
	//                  cveDetailsBaseURL,
	//                  d.VulnInfo.CveID,
	//                  distroLinks(d, r.Family)[0].url,
	//                  packsVer,
	//                  d.VulnInfo.Confidence,
	//              )
	//              scols = []string{
	//                  d.VulnInfo.CveID,
	//                  fmt.Sprintf("%-4.1f (%s)",
	//                      d.CvssV2Score(),
	//                      "TODO",
	//                  ),
	//                  summary,
	//              }
	//          default:
	//              summary := fmt.Sprintf("%s\n%sConfidence: %v",
	//                  distroLinks(d, r.Family)[0].url, packsVer, d.VulnInfo.Confidence)
	//              scols = []string{
	//                  d.VulnInfo.CveID,
	//                  "?",
	//                  summary,
	//              }
	//          }

	//          cols := make([]interface{}, len(scols))
	//          for i := range cols {
	//              cols[i] = scols[i]
	//          }
	//          stable.AddRow(cols...)
	//          stable.AddRow("")
	//      }
	return fmt.Sprintf("%s\n%s\n", header, stable)
}

func formatFullPlainText(r models.ScanResult) string {
	serverInfo := r.ServerInfo()

	var buf bytes.Buffer
	for i := 0; i < len(serverInfo); i++ {
		buf.WriteString("=")
	}
	header := fmt.Sprintf("%s\n%s\n%s\t%s\n",
		r.ServerInfo(),
		buf.String(),
		r.CveSummary(),
		r.Packages.FormatUpdatablePacksSummary(),
	)

	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Scan with --debug to view the details\n%s\n\n",
			header, r.Errors)
	}

	//TODO
	//      if len(r.KnownCves) == 0 && len(r.UnknownCves) == 0 {
	//          return fmt.Sprintf(`
	//  %s
	//  No CVE-IDs are found in updatable packages.
	//  %s
	//  `, header, r.Packages.FormatUpdatablePacksSummary())
	//      }

	//      scoredReport, unscoredReport := []string{}, []string{}
	//      scoredReport, unscoredReport = formatPlainTextDetails(r, r.Family)

	//      unscored := ""
	//      if !config.Conf.IgnoreUnscoredCves {
	//          unscored = strings.Join(unscoredReport, "\n\n")
	//      }

	//      scored := strings.Join(scoredReport, "\n\n")
	//      detail := fmt.Sprintf(`
	//  %s

	//  %s
	//  `,
	//          scored,
	//          unscored,
	//      )
	//  return fmt.Sprintf("%s\n%s\n%s", header, detail, formatChangelogs(r))
	return ""
}

//TODO
func formatPlainTextDetails(r models.ScanResult, osFamily string) (scoredReport, unscoredReport []string) {
	//  for _, cve := range r.KnownCves {
	//      switch config.Conf.Lang {
	//      case "en":
	//          if 0 < cve.CveDetail.Nvd.CvssScore() {
	//              scoredReport = append(
	//                  scoredReport, formatPlainTextDetailsLangEn(cve, osFamily))
	//          } else {
	//              scoredReport = append(
	//                  scoredReport, formatPlainTextUnknownCve(cve, osFamily))
	//          }
	//      case "ja":
	//          if 0 < cve.CveDetail.Jvn.CvssScore() {
	//              scoredReport = append(
	//                  scoredReport, formatPlainTextDetailsLangJa(cve, osFamily))
	//          } else if 0 < cve.CveDetail.Nvd.CvssScore() {
	//              scoredReport = append(
	//                  scoredReport, formatPlainTextDetailsLangEn(cve, osFamily))
	//          } else {
	//              scoredReport = append(
	//                  scoredReport, formatPlainTextUnknownCve(cve, osFamily))
	//          }
	//      }
	//  }
	//  for _, cve := range r.UnknownCves {
	//      unscoredReport = append(
	//          unscoredReport, formatPlainTextUnknownCve(cve, osFamily))
	//  }
	return
}

//  func formatPlainTextUnknownCve(cveInfo models.CveInfo, osFamily string) string {
//      cveID := cveInfo.VulnInfo.CveID
//      dtable := uitable.New()
//      dtable.MaxColWidth = maxColWidth
//      dtable.Wrap = true
//      dtable.AddRow(cveID)
//      dtable.AddRow("-------------")
//      dtable.AddRow("Score", "?")
//      dtable.AddRow("NVD", fmt.Sprintf("%s/%s", nvdBaseURL, cveID))
//      dlinks := distroLinks(cveInfo, osFamily)
//      for _, link := range dlinks {
//          dtable.AddRow(link.title, link.url)
//      }
//      dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
//      dtable = addPackageInfos(dtable, cveInfo.Packages)
//      dtable = addCpeNames(dtable, cveInfo.CpeNames)
//      dtable.AddRow("Confidence", cveInfo.VulnInfo.Confidence)

//      return fmt.Sprintf("%s", dtable)
//  }

//TODO
//  func formatPlainTextDetailsLangJa(cveInfo models.CveInfo, osFamily string) string {
//  return "TODO"
//  cveDetail := cveInfo.CveDetail
//  cveID := cveDetail.CveID
//  jvn := cveDetail.Jvn

//  dtable := uitable.New()
//  dtable.MaxColWidth = maxColWidth
//  dtable.Wrap = true
//  dtable.AddRow(cveID)
//  dtable.AddRow("-------------")
//  if score := cveDetail.Jvn.CvssScore(); 0 < score {
//      dtable.AddRow("Score",
//          fmt.Sprintf("%4.1f (%s)",
//              cveDetail.Jvn.CvssScore(),
//              jvn.CvssSeverity(),
//          ))
//  } else {
//      dtable.AddRow("Score", "?")
//  }
//  dtable.AddRow("Vector", jvn.CvssVector())
//  dtable.AddRow("Title", jvn.CveTitle())
//  dtable.AddRow("Description", jvn.CveSummary())
//  dtable.AddRow(cveDetail.CweID(), cweURL(cveDetail.CweID()))
//  dtable.AddRow(cveDetail.CweID()+"(JVN)", cweJvnURL(cveDetail.CweID()))

//  dtable.AddRow("JVN", jvn.Link())
//  dtable.AddRow("NVD", fmt.Sprintf("%s/%s", nvdBaseURL, cveID))
//  dtable.AddRow("MITRE", fmt.Sprintf("%s%s", mitreBaseURL, cveID))
//  dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
//  dtable.AddRow("CVSSv2 Clac", fmt.Sprintf(cvssV2CalcBaseURL, cveID))
//  dtable.AddRow("CVSSv3 Clac", fmt.Sprintf(cvssV3CalcBaseURL, cveID))

//  dlinks := distroLinks(cveInfo, osFamily)
//  for _, link := range dlinks {
//      dtable.AddRow(link.title, link.url)
//  }

//  dtable = addPackageInfos(dtable, cveInfo.Packages)
//  dtable = addCpeNames(dtable, cveInfo.CpeNames)
//  dtable.AddRow("Confidence", cveInfo.VulnInfo.Confidence)

//  return fmt.Sprintf("%s", dtable)
//  }

//TODO
//  func formatPlainTextDetailsLangEn(d models.CveInfo, osFamily string) string {
//  return ""
//  cveDetail := d.CveDetail
//  cveID := cveDetail.CveID
//  nvd := cveDetail.Nvd

//  dtable := uitable.New()
//  dtable.MaxColWidth = maxColWidth
//  dtable.Wrap = true
//  dtable.AddRow(cveID)
//  dtable.AddRow("-------------")

//  if score := cveDetail.Nvd.CvssScore(); 0 < score {
//      dtable.AddRow("Score",
//          fmt.Sprintf("%4.1f (%s)",
//              cveDetail.Nvd.CvssScore(),
//              nvd.CvssSeverity(),
//          ))
//  } else {
//      dtable.AddRow("Score", "?")
//  }

//  dtable.AddRow("Vector", nvd.CvssVector())
//  dtable.AddRow("Summary", nvd.CveSummary())
//  dtable.AddRow("CWE", cweURL(cveDetail.CweID()))

//  dtable.AddRow("NVD", fmt.Sprintf("%s/%s", nvdBaseURL, cveID))
//  dtable.AddRow("MITRE", fmt.Sprintf("%s%s", mitreBaseURL, cveID))
//  dtable.AddRow("CVE Details", fmt.Sprintf("%s/%s", cveDetailsBaseURL, cveID))
//  dtable.AddRow("CVSSv2 Clac", fmt.Sprintf(cvssV2CalcBaseURL, cveID))
//  dtable.AddRow("CVSSv3 Clac", fmt.Sprintf(cvssV3CalcBaseURL, cveID))

//  links := distroLinks(d, osFamily)
//  for _, link := range links {
//      dtable.AddRow(link.title, link.url)
//  }
//  dtable = addPackageInfos(dtable, d.Packages)
//  dtable = addCpeNames(dtable, d.CpeNames)
//  dtable.AddRow("Confidence", d.VulnInfo.Confidence)

//  return fmt.Sprintf("%s\n", dtable)
//  }

type distroLink struct {
	title string
	url   string
}

// distroLinks add Vendor URL of the CVE to table
//  func distroLinks(cveInfo models.CveInfo, osFamily string) []distroLink {
//      cveID := cveInfo.VulnInfo.CveID
//      switch osFamily {
//      case "rhel", "centos":
//          links := []distroLink{
//              {
//                  "RHEL-CVE",
//                  fmt.Sprintf("%s/%s", redhatSecurityBaseURL, cveID),
//              },
//          }
//          for _, advisory := range cveInfo.DistroAdvisories {
//              aidURL := strings.Replace(advisory.AdvisoryID, ":", "-", -1)
//              links = append(links, distroLink{
//                  //  "RHEL-errata",
//                  advisory.AdvisoryID,
//                  fmt.Sprintf(redhatRHSABaseBaseURL, aidURL),
//              })
//          }
//          return links
//      case "oraclelinux":
//          links := []distroLink{
//              {
//                  "Oracle-CVE",
//                  fmt.Sprintf(oracleSecurityBaseURL, cveID),
//              },
//          }
//          for _, advisory := range cveInfo.DistroAdvisories {
//              links = append(links, distroLink{
//                  // "Oracle-ELSA"
//                  advisory.AdvisoryID,
//                  fmt.Sprintf(oracleELSABaseBaseURL, advisory.AdvisoryID),
//              })
//          }
//          return links
//      case "amazon":
//          links := []distroLink{
//              {
//                  "RHEL-CVE",
//                  fmt.Sprintf("%s/%s", redhatSecurityBaseURL, cveID),
//              },
//          }
//          for _, advisory := range cveInfo.DistroAdvisories {
//              links = append(links, distroLink{
//                  //  "Amazon-ALAS",
//                  advisory.AdvisoryID,
//                  fmt.Sprintf(amazonSecurityBaseURL, advisory.AdvisoryID),
//              })
//          }
//          return links
//      case "ubuntu":
//          return []distroLink{
//              {
//                  "Ubuntu-CVE",
//                  fmt.Sprintf("%s/%s", ubuntuSecurityBaseURL, cveID),
//              },
//              //TODO Ubuntu USN
//          }
//      case "debian":
//          return []distroLink{
//              {
//                  "Debian-CVE",
//                  fmt.Sprintf("%s/%s", debianTrackerBaseURL, cveID),
//              },
//              //  TODO Debian dsa
//          }
//      case "FreeBSD":
//          links := []distroLink{}
//          for _, advisory := range cveInfo.DistroAdvisories {
//              links = append(links, distroLink{
//                  "FreeBSD-VuXML",
//                  fmt.Sprintf(freeBSDVuXMLBaseURL, advisory.AdvisoryID),
//              })
//          }
//          return links
//      default:
//          return []distroLink{}
//      }
//  }

// addPackages add package information related the CVE to table
func addPackages(table *uitable.Table, packs []models.Package) *uitable.Table {
	for i, p := range packs {
		var title string
		if i == 0 {
			title = "Package"
		}
		ver := fmt.Sprintf(
			"%s -> %s", p.FormatCurrentVer(), p.FormatNewVer())
		table.AddRow(title, ver)
	}
	return table
}

func addCpeNames(table *uitable.Table, names []string) *uitable.Table {
	for _, n := range names {
		table.AddRow("CPE", fmt.Sprintf("%s", n))
	}
	return table
}

func cweURL(cweID string) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
		strings.TrimPrefix(cweID, "CWE-"))
}

func cweJvnURL(cweID string) string {
	return fmt.Sprintf("http://jvndb.jvn.jp/ja/cwe/%s.html", cweID)
}

func formatChangelogs(r models.ScanResult) string {
	buf := []string{}
	for _, p := range r.Packages {
		if p.NewVersion == "" {
			continue
		}
		clog := formatOneChangelog(p)
		buf = append(buf, clog, "\n\n")
	}
	return strings.Join(buf, "\n")
}

func formatOneChangelog(p models.Package) string {
	buf := []string{}
	if p.NewVersion == "" {
		return ""
	}

	packVer := fmt.Sprintf("%s -> %s",
		p.FormatCurrentVer(), p.FormatNewVer())
	var delim bytes.Buffer
	for i := 0; i < len(packVer); i++ {
		delim.WriteString("-")
	}

	clog := p.Changelog.Contents
	if lines := strings.Split(clog, "\n"); len(lines) != 0 {
		clog = strings.Join(lines[0:len(lines)-1], "\n")
	}

	switch p.Changelog.Method {
	case models.FailedToGetChangelog:
		clog = "No changelogs"
	case models.FailedToFindVersionInChangelog:
		clog = "Failed to parse changelogs. For detials, check yourself"
	}
	buf = append(buf, packVer, delim.String(), clog)
	return strings.Join(buf, "\n")
}
