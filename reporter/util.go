package reporter

import (
	"bytes"
	"encoding/csv"
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
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/gosuri/uitable"
	"github.com/olekukonko/tablewriter"
	"golang.org/x/xerrors"
)

const (
	maxColWidth = 100
)

// OverwriteJSONFile overwrites scanresults JSON in the dir
func OverwriteJSONFile(dir string, r models.ScanResult) error {
	w := LocalFileWriter{
		CurrentDir: dir,
		FormatJSON: true,
	}
	if err := w.Write(r); err != nil {
		return xerrors.Errorf("Failed to write summary report: %w", err)
	}
	return nil
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

// jsonDirPattern is file name pattern of JSON directory
// 2016-11-16T10:43:28+09:00
// 2016-11-16T10:43:28Z
var jsonDirPattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$`)

// ListValidJSONDirs returns valid json directory as array
// Returned array is sorted so that recent directories are at the head
func ListValidJSONDirs(resultsDir string) (dirs []string, err error) {
	var dirInfo []os.FileInfo
	if dirInfo, err = ioutil.ReadDir(resultsDir); err != nil {
		err = xerrors.Errorf("Failed to read %s: %w", resultsDir, err)
		return
	}
	for _, d := range dirInfo {
		if d.IsDir() && jsonDirPattern.MatchString(d.Name()) {
			jsonDir := filepath.Join(resultsDir, d.Name())
			dirs = append(dirs, jsonDir)
		}
	}
	sort.Slice(dirs, func(i, j int) bool {
		return dirs[j] < dirs[i]
	})
	return
}

// JSONDir returns
// If there is args, check if it is a valid format and return the corresponding path under results.
// If arg passed via PIPE (such as history subcommand), return that path.
// Otherwise, returns the path of the latest directory
func JSONDir(resultsDir string, args []string) (path string, err error) {
	var dirs []string

	if 0 < len(args) {
		if dirs, err = ListValidJSONDirs(resultsDir); err != nil {
			return "", err
		}
		path = filepath.Join(resultsDir, args[0])
		for _, d := range dirs {
			ss := strings.Split(d, string(os.PathSeparator))
			timedir := ss[len(ss)-1]
			if timedir == args[0] {
				return path, nil
			}
		}
		return "", xerrors.Errorf("Invalid path: %s", path)
	}

	// TODO remove Pipe flag
	if config.Conf.Pipe {
		bytes, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			return "", xerrors.Errorf("Failed to read stdin: %w", err)
		}
		fields := strings.Fields(string(bytes))
		if 0 < len(fields) {
			return filepath.Join(resultsDir, fields[0]), nil
		}
		return "", xerrors.Errorf("Stdin is invalid: %s", string(bytes))
	}

	// returns latest dir when no args or no PIPE
	if dirs, err = ListValidJSONDirs(resultsDir); err != nil {
		return "", err
	}
	if len(dirs) == 0 {
		return "", xerrors.Errorf("No results under %s", resultsDir)
	}
	return dirs[0], nil
}

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
				r.FormatUpdatablePkgsSummary(),
			}
			if 0 < len(r.WordPressPackages) {
				cols = append(cols, fmt.Sprintf("%d WordPress pkgs", len(r.WordPressPackages)))
			}
			if 0 < len(r.LibraryScanners) {
				cols = append(cols, fmt.Sprintf("%d libs", r.LibraryScanners.Total()))
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
			warnMsgs = append(warnMsgs, fmt.Sprintf("Warning: %s", r.Warnings))
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
				r.FormatUpdatablePkgsSummary(),
				r.FormatExploitCveSummary(),
				r.FormatMetasploitCveSummary(),
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
	// TODO Don't use global variable
	if config.Conf.Quiet {
		return fmt.Sprintf("%s\n", table)
	}
	return fmt.Sprintf("%s\n\n%s", table, strings.Join(
		warnMsgs, "\n\n"))
}

func formatList(r models.ScanResult) string {
	header := r.FormatTextReportHeader()
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
`, header, r.FormatUpdatablePkgsSummary())
	}

	data := [][]string{}
	for _, vinfo := range r.ScannedCves.ToSortedSlice() {
		max := vinfo.MaxCvssScore().Value.Score
		// v2max := vinfo.MaxCvss2Score().Value.Score
		// v3max := vinfo.MaxCvss3Score().Value.Score

		// packname := vinfo.AffectedPackages.FormatTuiSummary()
		// packname += strings.Join(vinfo.CpeURIs, ", ")

		exploits := ""
		if 0 < len(vinfo.Exploits) || 0 < len(vinfo.Metasploits) {
			exploits = "POC"
		}

		link := ""
		if strings.HasPrefix(vinfo.CveID, "CVE-") {
			link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vinfo.CveID)
		} else if strings.HasPrefix(vinfo.CveID, "WPVDBID-") {
			link = fmt.Sprintf("https://wpscan.com/vulnerabilities/%s", strings.TrimPrefix(vinfo.CveID, "WPVDBID-"))
		}

		data = append(data, []string{
			vinfo.CveIDDiffFormat(),
			fmt.Sprintf("%4.1f", max),
			fmt.Sprintf("%5s", vinfo.AttackVector()),
			// fmt.Sprintf("%4.1f", v2max),
			// fmt.Sprintf("%4.1f", v3max),
			exploits,
			vinfo.AlertDict.FormatSource(),
			fmt.Sprintf("%7s", vinfo.PatchStatus(r.Packages)),
			link,
		})
	}

	b := bytes.Buffer{}
	table := tablewriter.NewWriter(&b)
	table.SetHeader([]string{
		"CVE-ID",
		"CVSS",
		"Attack",
		// "v3",
		// "v2",
		"PoC",
		"CERT",
		"Fixed",
		"NVD",
	})
	table.SetBorder(true)
	table.AppendBulk(data)
	table.Render()
	return fmt.Sprintf("%s\n%s", header, b.String())
}

func formatFullPlainText(r models.ScanResult) (lines string) {
	header := r.FormatTextReportHeader()
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
`, header, r.FormatUpdatablePkgsSummary())
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

		for _, cvss := range vuln.Cvss2Scores() {
			if cvssstr := cvss.Value.Format(); cvssstr != "" {
				data = append(data, []string{string(cvss.Type), cvssstr})
			}
		}

		data = append(data, []string{"Summary", vuln.Summaries(
			r.Lang, r.Family)[0].Value})

		for _, m := range vuln.Mitigations {
			data = append(data, []string{"Mitigation", m.URL})
		}

		links := vuln.CveContents.PrimarySrcURLs(r.Lang, r.Family, vuln.CveID)
		for _, link := range links {
			data = append(data, []string{"Primary Src", link.Value})
		}

		for _, url := range vuln.CveContents.PatchURLs() {
			data = append(data, []string{"Patch", url})
		}

		vuln.AffectedPackages.Sort()
		for _, affected := range vuln.AffectedPackages {
			if pack, ok := r.Packages[affected.Name]; ok {
				var line string
				if pack.Repository != "" {
					line = fmt.Sprintf("%s (%s)",
						pack.FormatVersionFromTo(affected),
						pack.Repository)
				} else {
					line = pack.FormatVersionFromTo(affected)
				}
				data = append(data, []string{"Affected Pkg", line})

				if len(pack.AffectedProcs) != 0 {
					for _, p := range pack.AffectedProcs {
						if len(p.ListenPortStats) == 0 {
							data = append(data, []string{"",
								fmt.Sprintf("  - PID: %s %s, Port: []", p.PID, p.Name)})
						}

						var ports []string
						for _, pp := range p.ListenPortStats {
							if len(pp.PortReachableTo) == 0 {
								ports = append(ports, fmt.Sprintf("%s:%s", pp.BindAddress, pp.Port))
							} else {
								ports = append(ports, fmt.Sprintf("%s:%s(◉ Scannable: %s)", pp.BindAddress, pp.Port, pp.PortReachableTo))
							}
						}

						data = append(data, []string{"",
							fmt.Sprintf("  - PID: %s %s, Port: %s", p.PID, p.Name, ports)})
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

		for _, l := range vuln.LibraryFixedIns {
			libs := r.LibraryScanners.Find(l.Path, l.Name)
			for path, lib := range libs {
				data = append(data, []string{l.Key,
					fmt.Sprintf("%s-%s, FixedIn: %s (%s)",
						lib.Name, lib.Version, l.FixedIn, path)})
			}
		}

		for _, confidence := range vuln.Confidences {
			data = append(data, []string{"Confidence", confidence.String()})
		}

		cweURLs, top10URLs := []string{}, []string{}
		cweTop25URLs, sansTop25URLs := []string{}, []string{}
		for _, v := range vuln.CveContents.UniqCweIDs(r.Family) {
			name, url, top10Rank, top10URL, cweTop25Rank, cweTop25URL, sansTop25Rank, sansTop25URL := r.CweDict.Get(v.Value, r.Lang)
			if top10Rank != "" {
				data = append(data, []string{"CWE",
					fmt.Sprintf("[OWASP Top%s] %s: %s (%s)",
						top10Rank, v.Value, name, v.Type)})
				top10URLs = append(top10URLs, top10URL)
			}
			if cweTop25Rank != "" {
				data = append(data, []string{"CWE",
					fmt.Sprintf("[CWE Top%s] %s: %s (%s)",
						cweTop25Rank, v.Value, name, v.Type)})
				cweTop25URLs = append(cweTop25URLs, cweTop25URL)
			}
			if sansTop25Rank != "" {
				data = append(data, []string{"CWE",
					fmt.Sprintf("[CWE/SANS Top%s]  %s: %s (%s)",
						sansTop25Rank, v.Value, name, v.Type)})
				sansTop25URLs = append(sansTop25URLs, sansTop25URL)
			}
			if top10Rank == "" && cweTop25Rank == "" && sansTop25Rank == "" {
				data = append(data, []string{"CWE", fmt.Sprintf("%s: %s (%s)",
					v.Value, name, v.Type)})
			}
			cweURLs = append(cweURLs, url)
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
		if len(cweTop25URLs) != 0 {
			data = append(data, []string{"CWE Top25", cweTop25URLs[0]})
		}
		if len(sansTop25URLs) != 0 {
			data = append(data, []string{"SANS/CWE Top25", sansTop25URLs[0]})
		}

		for _, alert := range vuln.AlertDict.Ja {
			data = append(data, []string{"JPCERT Alert", alert.URL})
		}

		for _, alert := range vuln.AlertDict.En {
			data = append(data, []string{"US-CERT Alert", alert.URL})
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
			vuln.CveIDDiffFormat(),
			vuln.PatchStatus(r.Packages),
		})
		table.SetBorder(true)
		table.AppendBulk(data)
		table.Render()
		lines += b.String() + "\n"
	}
	return
}

func formatCsvList(r models.ScanResult, path string) error {
	data := [][]string{{"CVE-ID", "CVSS", "Attack", "PoC", "CERT", "Fixed", "NVD"}}
	for _, vinfo := range r.ScannedCves.ToSortedSlice() {
		max := vinfo.MaxCvssScore().Value.Score

		exploits := ""
		if 0 < len(vinfo.Exploits) || 0 < len(vinfo.Metasploits) {
			exploits = "POC"
		}

		link := ""
		if strings.HasPrefix(vinfo.CveID, "CVE-") {
			link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vinfo.CveID)
		} else if strings.HasPrefix(vinfo.CveID, "WPVDBID-") {
			link = fmt.Sprintf("https://wpscan.com/vulnerabilities/%s", strings.TrimPrefix(vinfo.CveID, "WPVDBID-"))
		}

		data = append(data, []string{
			vinfo.CveID,
			fmt.Sprintf("%4.1f", max),
			vinfo.AttackVector(),
			exploits,
			vinfo.AlertDict.FormatSource(),
			vinfo.PatchStatus(r.Packages),
			link,
		})
	}

	file, err := os.Create(path)
	if err != nil {
		return xerrors.Errorf("Failed to create a file: %s, err: %w", path, err)
	}
	defer file.Close()
	if err := csv.NewWriter(file).WriteAll(data); err != nil {
		return xerrors.Errorf("Failed to write to file: %s, err: %w", path, err)
	}
	return nil
}

func cweURL(cweID string) string {
	return fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html",
		strings.TrimPrefix(cweID, "CWE-"))
}

func cweJvnURL(cweID string) string {
	return fmt.Sprintf("http://jvndb.jvn.jp/ja/cwe/%s.html", cweID)
}

func diff(curResults, preResults models.ScanResults, isPlus, isMinus bool) (diffed models.ScanResults) {
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

		if !found {
			diffed = append(diffed, current)
			continue
		}

		cves := models.VulnInfos{}
		if isPlus {
			cves = getPlusDiffCves(previous, current)
		}
		if isMinus {
			minus := getMinusDiffCves(previous, current)
			if len(cves) == 0 {
				cves = minus
			} else {
				for k, v := range minus {
					cves[k] = v
				}
			}
		}

		packages := models.Packages{}
		for _, s := range cves {
			for _, affected := range s.AffectedPackages {
				var p models.Package
				if s.DiffStatus == models.DiffPlus {
					p = current.Packages[affected.Name]
				} else {
					p = previous.Packages[affected.Name]
				}
				packages[affected.Name] = p
			}
		}
		current.ScannedCves = cves
		current.Packages = packages
		diffed = append(diffed, current)
	}
	return
}

func getPlusDiffCves(previous, current models.ScanResult) models.VulnInfos {
	previousCveIDsSet := map[string]bool{}
	for _, previousVulnInfo := range previous.ScannedCves {
		previousCveIDsSet[previousVulnInfo.CveID] = true
	}

	new := models.VulnInfos{}
	updated := models.VulnInfos{}
	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(v.CveID, previous, current) {
				v.DiffStatus = models.DiffPlus
				updated[v.CveID] = v
				logging.Log.Debugf("updated: %s", v.CveID)

				// TODO commented out because  a bug of diff logic when multiple oval defs found for a certain CVE-ID and same updated_at
				// if these OVAL defs have different affected packages, this logic detects as updated.
				// This logic will be uncomented after integration with gost https://github.com/knqyf263/gost
				// } else if isCveFixed(v, previous) {
				// updated[v.CveID] = v
				// logging.Log.Debugf("fixed: %s", v.CveID)

			} else {
				logging.Log.Debugf("same: %s", v.CveID)
			}
		} else {
			logging.Log.Debugf("new: %s", v.CveID)
			v.DiffStatus = models.DiffPlus
			new[v.CveID] = v
		}
	}

	if len(updated) == 0 && len(new) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	for cveID, vuln := range new {
		updated[cveID] = vuln
	}
	return updated
}

func getMinusDiffCves(previous, current models.ScanResult) models.VulnInfos {
	currentCveIDsSet := map[string]bool{}
	for _, currentVulnInfo := range current.ScannedCves {
		currentCveIDsSet[currentVulnInfo.CveID] = true
	}

	clear := models.VulnInfos{}
	for _, v := range previous.ScannedCves {
		if !currentCveIDsSet[v.CveID] {
			v.DiffStatus = models.DiffMinus
			clear[v.CveID] = v
			logging.Log.Debugf("clear: %s", v.CveID)
		}
	}
	if len(clear) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	return clear
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := []models.CveContentType{
		models.Nvd,
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
			logging.Log.Debugf("%s LastModified not equal: \n%s\n%s",
				cveID, curLastModified[t], prevLastModified[t])
			return true
		}
	}
	return false
}
