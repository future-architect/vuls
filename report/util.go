/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
	"github.com/gosuri/uitable"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/xerrors"
)

const maxColWidth = 100

func formatScanSummary(rs ...models.ScanResult) string {
	table := uitable.New()
	table.MaxColWidth = maxColWidth
	table.Wrap = true

	warnMsgs := []string{}
	for _, r := range rs {
		var cols []interface{}
		if len(r.Errors) == 0 {
			cols = []interface{}{
				r.FormatServerName(),
				fmt.Sprintf("%s%s", r.Family, r.Release),
				r.FormatUpdatablePacksSummary(),
			}
		} else {
			cols = []interface{}{
				r.FormatServerName(),
				"Error",
				"",
				"Use configtest subcommand or scan with --debug to view the details",
			}
		}
		table.AddRow(cols...)

		if len(r.Warnings) != 0 {
			warnMsgs = append(warnMsgs, fmt.Sprintf("Warning for %s: %s",
				r.FormatServerName(), r.Warnings))
		}
	}
	return fmt.Sprintf("%s\n\n%s", table, strings.Join(
		warnMsgs, "\n\n"))
}

func formatOneLineSummary(rs ...models.ScanResult) string {
	table := uitable.New()
	table.MaxColWidth = maxColWidth
	table.Wrap = true

	warnMsgs := []string{}
	for _, r := range rs {
		var cols []interface{}
		if len(r.Errors) == 0 {
			cols = []interface{}{
				r.FormatServerName(),
				r.ScannedCves.FormatCveSummary(),
				r.ScannedCves.FormatFixedStatus(r.Packages),
				r.FormatUpdatablePacksSummary(),
				r.FormatExploitCveSummary(),
				r.FormatAlertSummary(),
			}
		} else {
			cols = []interface{}{
				r.FormatServerName(),
				"Use configtest subcommand or scan with --debug to view the details",
				"",
			}
		}
		table.AddRow(cols...)

		if len(r.Warnings) != 0 {
			warnMsgs = append(warnMsgs, fmt.Sprintf("Warning for %s: %s",
				r.FormatServerName(), r.Warnings))
		}
	}
	// We don't want warning message to the summary file
	if config.Conf.Quiet {
		return fmt.Sprintf("%s\n", table)
	}
	return fmt.Sprintf("%s\n\n%s", table, strings.Join(
		warnMsgs, "\n\n"))
}

func formatList(r models.ScanResult) string {
	header := r.FormatTextReportHeadedr()
	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Use configtest subcommand or scan with --debug to view the details\n%s\n\n",
			header, r.Errors)
	}
	if len(r.Warnings) != 0 {
		header += fmt.Sprintf(
			"\nWarning: Some warnings occurred.\n%s\n\n",
			r.Warnings)
	}

	if len(r.ScannedCves) == 0 {
		return fmt.Sprintf(`
%s
No CVE-IDs are found in updatable packages.
%s
`, header, r.FormatUpdatablePacksSummary())
	}

	data := [][]string{}
	for _, vinfo := range r.ScannedCves.ToSortedSlice() {
		max := vinfo.MaxCvssScore().Value.Score
		// v2max := vinfo.MaxCvss2Score().Value.Score
		// v3max := vinfo.MaxCvss3Score().Value.Score

		// packname := vinfo.AffectedPackages.FormatTuiSummary()
		// packname += strings.Join(vinfo.CpeURIs, ", ")

		exploits := ""
		if 0 < len(vinfo.Exploits) {
			exploits = "   Y"
		}

		link := ""
		if strings.HasPrefix(vinfo.CveID, "CVE-") {
			link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vinfo.CveID)
		} else if strings.HasPrefix(vinfo.CveID, "WPVDBID-") {
			link = fmt.Sprintf("https://wpvulndb.com/vulnerabilities/%s", strings.TrimPrefix(vinfo.CveID, "WPVDBID-"))
		}

		data = append(data, []string{
			vinfo.CveID,
			fmt.Sprintf("%7s", vinfo.PatchStatus(r.Packages)),
			vinfo.AlertDict.FormatSource(),
			fmt.Sprintf("%4.1f", max),
			// fmt.Sprintf("%4.1f", v2max),
			// fmt.Sprintf("%4.1f", v3max),
			fmt.Sprintf("%2s", vinfo.AttackVector()),
			exploits,
			link,
		})
	}

	b := bytes.Buffer{}
	table := tablewriter.NewWriter(&b)
	table.SetHeader([]string{
		"CVE-ID",
		"Fixed",
		"CERT",
		"CVSS",
		// "v3",
		// "v2",
		"AV",
		"PoC",
		"NVD",
	})
	table.SetBorder(true)
	table.AppendBulk(data)
	table.Render()
	return fmt.Sprintf("%s\n%s", header, b.String())
}

func formatFullPlainText(r models.ScanResult) (lines string) {
	header := r.FormatTextReportHeadedr()
	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Use configtest subcommand or scan with --debug to view the details\n%s\n\n",
			header, r.Errors)
	}

	if len(r.Warnings) != 0 {
		header += fmt.Sprintf(
			"\nWarning: Some warnings occurred.\n%s\n\n",
			r.Warnings)
	}

	if len(r.ScannedCves) == 0 {
		return fmt.Sprintf(`
%s
No CVE-IDs are found in updatable packages.
%s
`, header, r.FormatUpdatablePacksSummary())
	}

	lines = header + "\n"

	for _, vuln := range r.ScannedCves.ToSortedSlice() {
		data := [][]string{}
		data = append(data, []string{"Max Score", vuln.FormatMaxCvssScore()})
		for _, cvss := range vuln.Cvss3Scores() {
			if cvssstr := cvss.Value.Format(); cvssstr != "" {
				data = append(data, []string{string(cvss.Type), cvssstr})
			}
		}

		for _, cvss := range vuln.Cvss2Scores(r.Family) {
			if cvssstr := cvss.Value.Format(); cvssstr != "" {
				data = append(data, []string{string(cvss.Type), cvssstr})
			}
		}

		data = append(data, []string{"Summary", vuln.Summaries(
			config.Conf.Lang, r.Family)[0].Value})

		mitigation := vuln.Mitigations(r.Family)[0]
		if mitigation.Type != models.Unknown {
			data = append(data, []string{"Mitigation", mitigation.Value})
		}

		cweURLs, top10URLs := []string{}, []string{}
		for _, v := range vuln.CveContents.UniqCweIDs(r.Family) {
			name, url, top10Rank, top10URL := r.CweDict.Get(v.Value, r.Lang)
			if top10Rank != "" {
				data = append(data, []string{"CWE",
					fmt.Sprintf("[OWASP Top%s] %s: %s (%s)",
						top10Rank, v.Value, name, v.Type)})
				top10URLs = append(top10URLs, top10URL)
			} else {
				data = append(data, []string{"CWE", fmt.Sprintf("%s: %s (%s)",
					v.Value, name, v.Type)})
			}
			cweURLs = append(cweURLs, url)
		}

		vuln.AffectedPackages.Sort()
		for _, affected := range vuln.AffectedPackages {
			if pack, ok := r.Packages[affected.Name]; ok {
				var line string
				if pack.Repository != "" {
					line = fmt.Sprintf("%s (%s)",
						pack.FormatVersionFromTo(affected.NotFixedYet, affected.FixState),
						pack.Repository)
				} else {
					line = fmt.Sprintf("%s",
						pack.FormatVersionFromTo(affected.NotFixedYet, affected.FixState),
					)
				}
				data = append(data, []string{"Affected Pkg", line})

				if len(pack.AffectedProcs) != 0 {
					for _, p := range pack.AffectedProcs {
						data = append(data, []string{"",
							fmt.Sprintf("  - PID: %s %s, Port: %s", p.PID, p.Name, p.ListenPorts)})
					}
				}
			}
		}
		sort.Strings(vuln.CpeURIs)
		for _, name := range vuln.CpeURIs {
			data = append(data, []string{"CPE", name})
		}

		for _, alert := range vuln.GitHubSecurityAlerts {
			data = append(data, []string{"GitHub", alert.PackageName})
		}

		for _, wp := range vuln.WpPackageFixStats {
			if p, ok := r.WordPressPackages.Find(wp.Name); ok {
				if p.Type == models.WPCore {
					data = append(data, []string{"WordPress",
						fmt.Sprintf("%s-%s, FixedIn: %s", wp.Name, p.Version, wp.FixedIn)})
				} else {
					data = append(data, []string{"WordPress",
						fmt.Sprintf("%s-%s, Update: %s, FixedIn: %s, %s",
							wp.Name, p.Version, p.Update, wp.FixedIn, p.Status)})
				}
			} else {
				data = append(data, []string{"WordPress",
					fmt.Sprintf("%s", wp.Name)})
			}
		}

		for _, confidence := range vuln.Confidences {
			data = append(data, []string{"Confidence", confidence.String()})
		}

		if strings.HasPrefix(vuln.CveID, "CVE-") {
			links := vuln.CveContents.SourceLinks(
				config.Conf.Lang, r.Family, vuln.CveID)
			data = append(data, []string{"Source", links[0].Value})

			if 0 < len(vuln.Cvss2Scores(r.Family)) {
				data = append(data, []string{"CVSSv2 Calc", vuln.Cvss2CalcURL()})
			}
			if 0 < len(vuln.Cvss3Scores()) {
				data = append(data, []string{"CVSSv3 Calc", vuln.Cvss3CalcURL()})
			}
		}

		vlinks := vuln.VendorLinks(r.Family)
		for name, url := range vlinks {
			data = append(data, []string{name, url})
		}
		for _, url := range cweURLs {
			data = append(data, []string{"CWE", url})
		}
		for _, exploit := range vuln.Exploits {
			data = append(data, []string{string(exploit.ExploitType), exploit.URL})
		}
		for _, url := range top10URLs {
			data = append(data, []string{"OWASP Top10", url})
		}

		for _, alert := range vuln.AlertDict.Ja {
			data = append(data, []string{"JPCERT Alert", alert.URL})
		}

		for _, alert := range vuln.AlertDict.En {
			data = append(data, []string{"USCERT Alert", alert.URL})
		}

		// for _, rr := range vuln.CveContents.References(r.Family) {
		// for _, ref := range rr.Value {
		// data = append(data, []string{ref.Source, ref.Link})
		// }
		// }

		b := bytes.Buffer{}
		table := tablewriter.NewWriter(&b)
		table.SetColWidth(80)
		table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
		table.SetHeader([]string{
			vuln.CveID,
			vuln.PatchStatus(r.Packages),
		})
		table.SetBorder(true)
		table.AppendBulk(data)
		table.Render()
		lines += b.String() + "\n"
	}
	return
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
		clog := p.FormatChangelog()
		buf = append(buf, clog, "\n\n")
	}
	return strings.Join(buf, "\n")
}
func ovalSupported(r *models.ScanResult) bool {
	switch r.Family {
	case
		config.Amazon,
		config.FreeBSD,
		config.Raspbian:
		return false
	}
	return true
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
		return xerrors.Errorf("Failed to write summary report: %w", err)
	}
	config.Conf.FormatJSON = before
	config.Conf.Diff = beforeDiff
	return nil
}

func loadPrevious(currs models.ScanResults) (prevs models.ScanResults, err error) {
	dirs, err := ListValidJSONDirs()
	if err != nil {
		return
	}

	for _, result := range currs {
		filename := result.ServerName + ".json"
		if result.Container.Name != "" {
			filename = fmt.Sprintf("%s@%s.json", result.Container.Name, result.ServerName)
		}
		for _, dir := range dirs[1:] {
			path := filepath.Join(dir, filename)
			r, err := loadOneServerScanResult(path)
			if err != nil {
				util.Log.Errorf("%+v", err)
				continue
			}
			if r.Family == result.Family && r.Release == result.Release {
				prevs = append(prevs, *r)
				util.Log.Infof("Previous json found: %s", path)
				break
			} else {
				util.Log.Infof("Previous json is different family.Release: %s, pre: %s.%s cur: %s.%s",
					path, r.Family, r.Release, result.Family, result.Release)
			}
		}
	}
	return prevs, nil
}

func diff(curResults, preResults models.ScanResults) (diffed models.ScanResults, err error) {
	for _, current := range curResults {
		found := false
		var previous models.ScanResult
		for _, r := range preResults {
			if current.ServerName == r.ServerName && current.Container.Name == r.Container.Name {
				found = true
				previous = r
				break
			}
		}

		if found {
			current.ScannedCves = getDiffCves(previous, current)
			packages := models.Packages{}
			for _, s := range current.ScannedCves {
				for _, affected := range s.AffectedPackages {
					p := current.Packages[affected.Name]
					packages[affected.Name] = p
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
				util.Log.Debugf("updated: %s", v.CveID)

				// TODO commented out beause  a bug of diff logic when multiple oval defs found for a certain CVE-ID and same updated_at
				// if these OVAL defs have different affected packages, this logic detects as updated.
				// This logic will be uncommented after integration with ghost https://github.com/knqyf263/gost
				// } else if isCveFixed(v, previous) {
				// updated[v.CveID] = v
				// util.Log.Debugf("fixed: %s", v.CveID)

			} else {
				util.Log.Debugf("same: %s", v.CveID)
			}
		} else {
			util.Log.Debugf("new: %s", v.CveID)
			new[v.CveID] = v
		}
	}

	for cveID, vuln := range new {
		updated[cveID] = vuln
	}
	return updated
}

func isCveFixed(current models.VulnInfo, previous models.ScanResult) bool {
	preVinfo, _ := previous.ScannedCves[current.CveID]
	pre := map[string]bool{}
	for _, h := range preVinfo.AffectedPackages {
		pre[h.Name] = h.NotFixedYet
	}

	cur := map[string]bool{}
	for _, h := range current.AffectedPackages {
		cur[h.Name] = h.NotFixedYet
	}

	return !reflect.DeepEqual(pre, cur)
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := []models.CveContentType{
		models.NvdXML,
		models.Jvn,
		models.NewCveContentType(current.Family),
	}

	prevLastModified := map[models.CveContentType]time.Time{}
	preVinfo, ok := previous.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if content, ok := preVinfo.CveContents[cType]; ok {
			prevLastModified[cType] = content.LastModified
		}
	}

	curLastModified := map[models.CveContentType]time.Time{}
	curVinfo, ok := current.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if content, ok := curVinfo.CveContents[cType]; ok {
			curLastModified[cType] = content.LastModified
		}
	}

	for _, t := range cTypes {
		if !curLastModified[t].Equal(prevLastModified[t]) {
			util.Log.Debugf("%s LastModified not equal: \n%s\n%s",
				cveID, curLastModified[t], prevLastModified[t])
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
		err = xerrors.Errorf("Failed to read %s: %w",
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

		return "", xerrors.Errorf("Invalid path: %s", path)
	}

	// PIPE
	if config.Conf.Pipe {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", xerrors.Errorf("Failed to read stdin: %w", err)
		}
		fields := strings.Fields(string(bytes))
		if 0 < len(fields) {
			return filepath.Join(config.Conf.ResultsDir, fields[0]), nil
		}
		return "", xerrors.Errorf("Stdin is invalid: %s", string(bytes))
	}

	// returns latest dir when no args or no PIPE
	if dirs, err = ListValidJSONDirs(); err != nil {
		return "", err
	}
	if len(dirs) == 0 {
		return "", xerrors.Errorf("No results under %s",
			config.Conf.ResultsDir)
	}
	return dirs[0], nil
}

// LoadScanResults read JSON data
func LoadScanResults(jsonDir string) (results models.ScanResults, err error) {
	var files []os.FileInfo
	if files, err = ioutil.ReadDir(jsonDir); err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", jsonDir, err)
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" || strings.HasSuffix(f.Name(), "_diff.json") {
			continue
		}

		var r *models.ScanResult
		path := filepath.Join(jsonDir, f.Name())
		if r, err = loadOneServerScanResult(path); err != nil {
			return nil, err
		}
		results = append(results, *r)
	}
	if len(results) == 0 {
		return nil, xerrors.Errorf("There is no json file under %s", jsonDir)
	}
	return
}

// loadOneServerScanResult read JSON data of one server
func loadOneServerScanResult(jsonFile string) (*models.ScanResult, error) {
	var (
		data []byte
		err  error
	)
	if data, err = ioutil.ReadFile(jsonFile); err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", jsonFile, err)
	}
	result := &models.ScanResult{}
	if err := json.Unmarshal(data, result); err != nil {
		return nil, xerrors.Errorf("Failed to parse %s: %w", jsonFile, err)
	}
	return result, nil
}
