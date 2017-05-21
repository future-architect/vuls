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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/gosuri/uitable"
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
				r.CveSummary(config.Conf.IgnoreUnscoredCves),
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
	header := r.FormatTextReportHeadedr()
	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Scan with --debug to view the details\n%s\n\n",
			header, r.Errors)
	}

	vulns := r.ScannedCves
	if !config.Conf.IgnoreUnscoredCves {
		vulns = vulns.FindScoredVulns()
	}

	if len(vulns) == 0 {
		return fmt.Sprintf(`
	 %s
	 No CVE-IDs are found in updatable packages.
	 %s
	 `, header, r.Packages.FormatUpdatablePacksSummary())
	}

	stable := uitable.New()
	stable.MaxColWidth = maxColWidth
	stable.Wrap = true
	for _, vuln := range vulns {
		summaries := vuln.CveContents.Summaries(config.Conf.Lang, r.Family)
		links := vuln.CveContents.SourceLinks(
			config.Conf.Lang, r.Family, vuln.CveID)

		cvsses := ""
		for _, cvss := range vuln.CveContents.Cvss2Scores() {
			cvsses += fmt.Sprintf("%s (%s)\n", cvss.Value.Format(), cvss.Type)
		}
		cvsses += vuln.Cvss2CalcURL() + "\n"
		for _, cvss := range vuln.CveContents.Cvss3Scores() {
			cvsses += fmt.Sprintf("%s (%s)\n", cvss.Value.Format(), cvss.Type)
		}
		if 0 < len(vuln.CveContents.Cvss3Scores()) {
			cvsses += vuln.Cvss3CalcURL() + "\n"
		}

		maxCvss := vuln.CveContents.FormatMaxCvssScore()
		rightCol := fmt.Sprintf(`%s
%s
---
%s
%sConfidence: %v`,
			maxCvss,
			summaries[0].Value,
			links[0].Value,
			cvsses,
			//  packsVer,
			vuln.Confidence,
		)

		leftCol := fmt.Sprintf("%s", vuln.CveID)
		scols := []string{leftCol, rightCol}
		cols := make([]interface{}, len(scols))
		for i := range cols {
			cols[i] = scols[i]
		}
		stable.AddRow(cols...)
		stable.AddRow("")
	}
	return fmt.Sprintf("%s\n%s\n", header, stable)
}

func formatFullPlainText(r models.ScanResult) string {
	header := r.FormatTextReportHeadedr()
	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Scan with --debug to view the details\n%s\n\n",
			header, r.Errors)
	}

	vulns := r.ScannedCves
	if !config.Conf.IgnoreUnscoredCves {
		vulns = vulns.FindScoredVulns()
	}

	if len(vulns) == 0 {
		return fmt.Sprintf(`
	 %s
	 No CVE-IDs are found in updatable packages.
	 %s
	 `, header, r.Packages.FormatUpdatablePacksSummary())
	}

	table := uitable.New()
	table.MaxColWidth = maxColWidth
	table.Wrap = true
	for _, vuln := range vulns {
		table.AddRow(vuln.CveID)
		table.AddRow("----------------")
		table.AddRow("Max Score", vuln.CveContents.FormatMaxCvssScore())
		for _, cvss := range vuln.CveContents.Cvss2Scores() {
			table.AddRow(cvss.Type, cvss.Value.Format())
		}
		for _, cvss := range vuln.CveContents.Cvss3Scores() {
			table.AddRow(cvss.Type, cvss.Value.Format())
		}
		if 0 < len(vuln.CveContents.Cvss2Scores()) {
			table.AddRow("CVSSv2 Calc", vuln.Cvss2CalcURL())
		}
		if 0 < len(vuln.CveContents.Cvss3Scores()) {
			table.AddRow("CVSSv3 Calc", vuln.Cvss3CalcURL())
		}
		table.AddRow("Summary", vuln.CveContents.Summaries(
			config.Conf.Lang, r.Family)[0].Value)

		links := vuln.CveContents.SourceLinks(
			config.Conf.Lang, r.Family, vuln.CveID)
		table.AddRow("Source", links[0].Value)

		vendorLink := vuln.CveContents.VendorLink(r.Family)
		table.AddRow(fmt.Sprintf("Vendor (%s)", vendorLink.Type), vendorLink.Value)

		for _, v := range vuln.CveContents.CweIDs(r.Family) {
			table.AddRow(fmt.Sprintf("%s (%s)", v.Value, v.Type), cweURL(v.Value))
		}

		packsVer := []string{}
		for _, name := range vuln.PackageNames {
			// packages detected by OVAL may not be actually installed
			if pack, ok := r.Packages[name]; ok {
				packsVer = append(packsVer, pack.FormatVersionFromTo())
			}
		}
		for _, name := range vuln.CpeNames {
			packsVer = append(packsVer, name)
		}
		table.AddRow("Package/CPE", strings.Join(packsVer, "\n"))
		table.AddRow("Confidence", vuln.Confidence)

		table.AddRow("\n")
	}

	return fmt.Sprintf("%s\n%s", header, table)
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

//  type distroLink struct {
//      title string
//      url   string
//  }

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
			"%s -> %s", p.FormatVer(), p.FormatNewVer())
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
		p.FormatVer(), p.FormatNewVer())
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

func needToRefreshCve(r models.ScanResult) bool {
	if r.Lang != config.Conf.Lang {
		return true
	}

	for _, cve := range r.ScannedCves {
		if 0 < len(cve.CveContents) {
			return false
		}
	}
	return true
}

func overwriteJSONFile(dir string, r models.ScanResult) error {
	before := config.Conf.FormatJSON
	beforeDiff := config.Conf.Diff
	config.Conf.FormatJSON = true
	config.Conf.Diff = false
	w := LocalFileWriter{CurrentDir: dir}
	if err := w.Write(r); err != nil {
		return fmt.Errorf("Failed to write summary report: %s", err)
	}
	config.Conf.FormatJSON = before
	config.Conf.Diff = beforeDiff
	return nil
}

func loadPrevious(current models.ScanResults) (previous models.ScanResults, err error) {
	dirs, err := ListValidJSONDirs()
	if err != nil {
		return
	}

	for _, result := range current {
		for _, dir := range dirs[1:] {
			var r models.ScanResult
			path := filepath.Join(dir, result.ServerName+".json")
			if r, err = loadOneServerScanResult(path); err != nil {
				continue
			}
			if r.Family == result.Family && r.Release == result.Release {
				previous = append(previous, r)
				util.Log.Infof("Privious json found: %s", path)
				break
			}
		}
	}
	return previous, nil
}

func diff(curResults, preResults models.ScanResults) (diffed models.ScanResults, err error) {
	for _, current := range curResults {
		found := false
		var previous models.ScanResult
		for _, r := range preResults {
			if current.ServerName == r.ServerName {
				found = true
				previous = r
				break
			}
		}

		if found {
			current.ScannedCves = getDiffCves(previous, current)
			packages := models.Packages{}
			for _, s := range current.ScannedCves {
				for _, name := range s.PackageNames {
					p := current.Packages[name]
					packages[name] = p
				}
			}
			current.Packages = packages
		}

		diffed = append(diffed, current)
	}
	return diffed, err
}

func getDiffCves(previous, current models.ScanResult) models.VulnInfos {
	previousCveIDsSet := map[string]bool{}
	for _, previousVulnInfo := range previous.ScannedCves {
		previousCveIDsSet[previousVulnInfo.CveID] = true
	}

	new := models.VulnInfos{}
	updated := models.VulnInfos{}
	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(v.CveID, previous, current) {
				updated[v.CveID] = v
			}
		} else {
			new[v.CveID] = v
		}
	}

	for cveID, vuln := range new {
		updated[cveID] = vuln
	}
	return updated
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := []models.CveContentType{
		models.NVD,
		models.JVN,
		models.NewCveContentType(current.Family),
	}

	prevLastModified := map[models.CveContentType]time.Time{}
	for _, c := range previous.ScannedCves {
		if cveID == c.CveID {
			for _, cType := range cTypes {
				content, _ := c.CveContents[cType]
				prevLastModified[cType] = content.LastModified
			}
			break
		}
	}

	curLastModified := map[models.CveContentType]time.Time{}
	for _, c := range current.ScannedCves {
		if cveID == c.CveID {
			for _, cType := range cTypes {
				content, _ := c.CveContents[cType]
				curLastModified[cType] = content.LastModified
			}
			break
		}
	}
	for _, cType := range cTypes {
		if equal := prevLastModified[cType].Equal(curLastModified[cType]); !equal {
			return true
		}
	}
	return false
}

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
// 2016-11-16T10:43:28Z
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$`)

// ListValidJSONDirs returns valid json directory as array
// Returned array is sorted so that recent directories are at the head
func ListValidJSONDirs() (dirs []string, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(config.Conf.ResultsDir); err != nil {
		err = fmt.Errorf("Failed to read %s: %s",
			config.Conf.ResultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && jsonDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(config.Conf.ResultsDir, d.Name())
			dirs = append(dirs, jsonDir)
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[j] < dirs[i]
	})
	return
}

// JSONDir returns
// If there is an arg, check if it is a valid format and return the corresponding path under results.
// If arg passed via PIPE (such as history subcommand), return that path.
// Otherwise, returns the path of the latest directory
func JSONDir(args []string) (string, error) {
	var err error
	dirs := []string{}

	if 0 < len(args) {
		if dirs, err = ListValidJSONDirs(); err != nil {
			return "", err
		}

		path := filepath.Join(config.Conf.ResultsDir, args[0])
		for _, d := range dirs {
			ss := strings.Split(d, string(os.PathSeparator))
			timedir := ss[len(ss)-1]
			if timedir == args[0] {
				return path, nil
			}
		}

		return "", fmt.Errorf("Invalid path: %s", path)
	}

	// PIPE
	if config.Conf.Pipe {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("Failed to read stdin: %s", err)
		}
		fields := strings.Fields(string(bytes))
		if 0 < len(fields) {
			return filepath.Join(config.Conf.ResultsDir, fields[0]), nil
		}
		return "", fmt.Errorf("Stdin is invalid: %s", string(bytes))
	}

	// returns latest dir when no args or no PIPE
	if dirs, err = ListValidJSONDirs(); err != nil {
		return "", err
	}
	if len(dirs) == 0 {
		return "", fmt.Errorf("No results under %s",
			config.Conf.ResultsDir)
	}
	return dirs[0], nil
}

// LoadScanResults read JSON data
func LoadScanResults(jsonDir string) (results models.ScanResults, err error) {
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		return nil, fmt.Errorf("Failed to read %s: %s", jsonDir, err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" || strings.HasSuffix(f.Name(), "_diff.json") {
			continue
		}

		var r models.ScanResult
		path := filepath.Join(jsonDir, f.Name())
		if r, err = loadOneServerScanResult(path); err != nil {
			return nil, err
		}

		results = append(results, r)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("There is no json file under %s", jsonDir)
	}
	return
}

// loadOneServerScanResult read JSON data of one server
func loadOneServerScanResult(jsonFile string) (result models.ScanResult, err error) {
	var data []byte
	if data, err = ioutil.ReadFile(jsonFile); err != nil {
		err = fmt.Errorf("Failed to read %s: %s", jsonFile, err)
		return
	}
	if json.Unmarshal(data, &result) != nil {
		err = fmt.Errorf("Failed to parse %s: %s", jsonFile, err)
	}
	return
}
