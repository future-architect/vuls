package reporter

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/cti"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/gosuri/uitable"
	"github.com/olekukonko/tablewriter"
	"github.com/olekukonko/tablewriter/renderer"
	"github.com/olekukonko/tablewriter/tw"
	"golang.org/x/term"
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
	var files []fs.DirEntry
	if files, err = os.ReadDir(jsonDir); err != nil {
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
	if data, err = os.ReadFile(jsonFile); err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", jsonFile, err)
	}
	result := &models.ScanResult{}
	if err := json.Unmarshal(data, result); err != nil {
		return nil, xerrors.Errorf("Failed to parse %s: %w", jsonFile, err)
	}
	return result, nil
}

// ListValidJSONDirs returns valid json directory as array
// Returned array is sorted so that recent directories are at the head
func ListValidJSONDirs(resultsDir string) (dirs []string, err error) {
	dirInfo, err := os.ReadDir(resultsDir)
	if err != nil {
		return nil, xerrors.Errorf("Failed to read %s: %w", resultsDir, err)
	}
	for _, d := range dirInfo {
		if !d.IsDir() {
			continue
		}

		for _, layout := range []string{"2006-01-02T15:04:05Z", "2006-01-02T15:04:05-07:00", "2006-01-02T15-04-05-0700"} {
			if _, err := time.Parse(layout, d.Name()); err == nil {
				dirs = append(dirs, filepath.Join(resultsDir, d.Name()))
				break
			}
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
		bytes, err := io.ReadAll(os.Stdin)
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
				r.FormatKEVCveSummary(),
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

func formatList(r models.ScanResult) (string, error) {
	header := r.FormatTextReportHeader()
	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Use configtest subcommand or scan with --debug to view the details\n%s\n\n",
			header, r.Errors), nil
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
`, header, r.FormatUpdatablePkgsSummary()), nil
	}

	data := [][]string{}
	for _, vinfo := range r.ScannedCves.ToSortedSlice() {
		score := vinfo.MaxCvssScore().Value.Score
		// v2max := vinfo.MaxCvss2Score().Value.Score
		// v3max := vinfo.MaxCvss3Score().Value.Score

		pkgNames := vinfo.AffectedPackages.Names()
		pkgNames = append(pkgNames, vinfo.CpeURIs...)
		pkgNames = append(pkgNames, vinfo.GitHubSecurityAlerts.Names()...)
		pkgNames = append(pkgNames, vinfo.WpPackageFixStats.Names()...)
		pkgNames = append(pkgNames, vinfo.LibraryFixedIns.Names()...)
		pkgNames = append(pkgNames, vinfo.WindowsKBFixedIns...)
		packnames := strings.Join(pkgNames, ", ")

		exploits := ""
		if 0 < len(vinfo.Exploits) || 0 < len(vinfo.Metasploits) {
			exploits = "POC"
		}

		// link := ""
		// if strings.HasPrefix(vinfo.CveID, "CVE-") {
		// 	link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", vinfo.CveID)
		// } else if strings.HasPrefix(vinfo.CveID, "WPVDBID-") {
		// 	link = fmt.Sprintf("https://wpscan.com/vulnerabilities/%s", strings.TrimPrefix(vinfo.CveID, "WPVDBID-"))
		// }

		data = append(data, []string{
			vinfo.CveIDDiffFormat(),
			fmt.Sprintf("%4.1f", score),
			fmt.Sprintf("%5s", vinfo.AttackVector()),
			// fmt.Sprintf("%4.1f", v2max),
			// fmt.Sprintf("%4.1f", v3max),
			exploits,
			func() string {
				if len(vinfo.KEVs) == 0 {
					return ""
				}
				if slices.ContainsFunc(vinfo.KEVs, func(e models.KEV) bool {
					return e.Type == models.CISAKEVType
				}) {
					return string(models.CISAKEVType)
				}
				return string(models.VulnCheckKEVType)
			}(),
			fmt.Sprintf("%9s", vinfo.AlertDict.FormatSource()),
			fmt.Sprintf("%7s", vinfo.PatchStatus(r.Packages)),
			packnames,
		})
	}

	b := bytes.Buffer{}
	table := tablewriter.NewTable(&b,
		tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
			Symbols:  tw.NewSymbols(tw.StyleASCII),
			Settings: tw.Settings{Separators: tw.Separators{BetweenRows: tw.On}},
		})),
		tablewriter.WithMaxWidth(terminalWidth()),
		tablewriter.WithHeaderAutoFormat(tw.Off),
		tablewriter.WithRowAutoFormat(tw.Off),
	)

	table.Header([]string{
		"CVE-ID",
		"CVSS",
		"Attack",
		// "v3",
		// "v2",
		"PoC",
		"KEV",
		"Alert",
		"Fixed",
		// "NVD",
		"Packages",
	})
	if err := table.Bulk(data); err != nil {
		return "", xerrors.Errorf("Failed to bulk to table. err: %w", err)
	}
	if err := table.Render(); err != nil {
		return "", xerrors.Errorf("Failed to render table. err: %w", err)
	}
	return fmt.Sprintf("%s\n%s", header, b.String()), nil
}

func formatFullPlainText(r models.ScanResult) (string, error) {
	header := r.FormatTextReportHeader()
	if len(r.Errors) != 0 {
		return fmt.Sprintf(
			"%s\nError: Use configtest subcommand or scan with --debug to view the details\n%s\n\n",
			header, r.Errors), nil
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
`, header, r.FormatUpdatablePkgsSummary()), nil
	}

	lines := header + "\n"

	for _, vuln := range r.ScannedCves.ToSortedSlice() {
		data := [][]string{}
		data = append(data, []string{"Max Score", vuln.FormatMaxCvssScore()})
		for _, cvss := range vuln.Cvss40Scores() {
			if cvssstr := cvss.Value.Format(); cvssstr != "" {
				data = append(data, []string{string(cvss.Type), cvssstr})
			}
		}
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

		for _, ssvc := range vuln.CveContents.SSVC() {
			data = append(data, []string{fmt.Sprintf("SSVC[%s]", ssvc.Type), fmt.Sprintf("Exploitation    : %s\nAutomatable     : %s\nTechnicalImpact : %s", ssvc.Value.Exploitation, ssvc.Value.Automatable, ssvc.Value.TechnicalImpact)})
		}

		data = append(data, []string{"Summary", vuln.Summaries(
			r.Lang, r.Family)[0].Value})

		for _, m := range vuln.Mitigations {
			data = append(data, []string{"Mitigation", m.URL})
		}

		links := vuln.CveContents.PrimarySrcURLs(r.Lang, r.Family, vuln.CveID, vuln.Confidences)
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

				for _, p := range pack.AffectedProcs {
					if len(p.ListenPortStats) == 0 {
						data = append(data, []string{"", fmt.Sprintf("  - PID: %s %s", p.PID, p.Name)})
						continue
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
		sort.Strings(vuln.CpeURIs)
		for _, name := range vuln.CpeURIs {
			data = append(data, []string{"CPE", name})
		}

		for _, alert := range vuln.GitHubSecurityAlerts {
			data = append(data, []string{"GitHub", alert.RepoURLPackageName()})
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
				data = append(data, []string{"WordPress", wp.Name})
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

		if len(vuln.WindowsKBFixedIns) > 0 {
			data = append(data, []string{"Windows KB", fmt.Sprintf("FixedIn: %s", strings.Join(vuln.WindowsKBFixedIns, ", "))})
		}

		for _, confidence := range vuln.Confidences {
			data = append(data, []string{"Confidence", confidence.String()})
		}

		cweURLs, top10URLs, cweTop25URLs, sansTop25URLs := []string{}, map[string][]string{}, map[string][]string{}, map[string][]string{}
		for _, v := range vuln.CveContents.UniqCweIDs(r.Family) {
			name, url, owasp, cwe25, sans := r.CweDict.Get(v.Value, r.Lang)

			ds := [][]string{}
			for year, info := range owasp {
				ds = append(ds, []string{"CWE", fmt.Sprintf("[OWASP(%s) Top%s] %s: %s (%s)", year, info.Rank, v.Value, name, v.Type)})
				top10URLs[year] = append(top10URLs[year], info.URL)
			}
			slices.SortFunc(ds, func(a, b []string) int {
				if a[1] < b[1] {
					return -1
				}
				if a[1] > b[1] {
					return +1
				}
				return 0
			})
			data = append(data, ds...)

			ds = [][]string{}
			for year, info := range cwe25 {
				ds = append(ds, []string{"CWE", fmt.Sprintf("[CWE(%s) Top%s] %s: %s (%s)", year, info.Rank, v.Value, name, v.Type)})
				cweTop25URLs[year] = append(cweTop25URLs[year], info.URL)
			}
			slices.SortFunc(ds, func(a, b []string) int {
				if a[1] < b[1] {
					return -1
				}
				if a[1] > b[1] {
					return +1
				}
				return 0
			})
			data = append(data, ds...)

			ds = [][]string{}
			for year, info := range sans {
				ds = append(ds, []string{"CWE", fmt.Sprintf("[CWE/SANS(%s) Top%s]  %s: %s (%s)", year, info.Rank, v.Value, name, v.Type)})
				sansTop25URLs[year] = append(sansTop25URLs[year], info.URL)
			}
			slices.SortFunc(ds, func(a, b []string) int {
				if a[1] < b[1] {
					return -1
				}
				if a[1] > b[1] {
					return +1
				}
				return 0
			})
			data = append(data, ds...)

			if len(owasp) == 0 && len(cwe25) == 0 && len(sans) == 0 {
				data = append(data, []string{"CWE", fmt.Sprintf("%s: %s (%s)", v.Value, name, v.Type)})
			}
			cweURLs = append(cweURLs, url)
		}

		for _, url := range cweURLs {
			data = append(data, []string{"CWE", url})
		}

		m := map[string]struct{}{}
		for _, exploit := range vuln.Exploits {
			if _, ok := m[exploit.URL]; ok {
				continue
			}
			data = append(data, []string{string(exploit.ExploitType), exploit.URL})
			m[exploit.URL] = struct{}{}
		}

		for year, urls := range top10URLs {
			ds := [][]string{}
			for _, url := range urls {
				ds = append(ds, []string{fmt.Sprintf("OWASP(%s) Top10", year), url})
			}
			slices.SortFunc(ds, func(a, b []string) int {
				if a[0] < b[0] {
					return -1
				}
				if a[0] > b[0] {
					return +1
				}
				return 0
			})
			data = append(data, ds...)
		}

		ds := [][]string{}
		for year, urls := range cweTop25URLs {
			ds = append(ds, []string{fmt.Sprintf("CWE(%s) Top25", year), urls[0]})
		}
		slices.SortFunc(ds, func(a, b []string) int {
			if a[0] < b[0] {
				return -1
			}
			if a[0] > b[0] {
				return +1
			}
			return 0
		})
		data = append(data, ds...)

		ds = [][]string{}
		for year, urls := range sansTop25URLs {
			ds = append(ds, []string{fmt.Sprintf("SANS/CWE(%s) Top25", year), urls[0]})
		}
		slices.SortFunc(ds, func(a, b []string) int {
			if a[0] < b[0] {
				return -1
			}
			if a[0] > b[0] {
				return +1
			}
			return 0
		})
		data = append(data, ds...)

		for _, alert := range vuln.AlertDict.JPCERT {
			data = append(data, []string{"JPCERT Alert", alert.URL})
		}

		for _, alert := range vuln.AlertDict.USCERT {
			data = append(data, []string{"US-CERT Alert", alert.URL})
		}

		attacks := []string{}
		for _, techniqueID := range vuln.Ctis {
			if strings.HasPrefix(techniqueID, "CAPEC-") {
				continue
			}
			technique, ok := cti.TechniqueDict[techniqueID]
			if !ok {
				continue
			}
			attacks = append(attacks, technique.Name)
		}
		slices.Sort(attacks)
		for _, attack := range attacks {
			data = append(data, []string{"MITER ATT&CK", attack})
		}

		// for _, rr := range vuln.CveContents.References(r.Family) {
		// for _, ref := range rr.Value {
		// data = append(data, []string{ref.Source, ref.Link})
		// }
		// }

		b := bytes.Buffer{}

		table := tablewriter.NewTable(&b,
			tablewriter.WithMaxWidth(terminalWidth()),
			tablewriter.WithRenderer(renderer.NewBlueprint(tw.Rendition{
				Symbols: tw.NewSymbols(tw.StyleASCII),
			})),
			tablewriter.WithHeaderAutoFormat(tw.Off),
			tablewriter.WithRowAutoFormat(tw.Off),
		)
		table.Header([]string{
			vuln.CveIDDiffFormat(),
			vuln.PatchStatus(r.Packages),
		})
		if err := table.Bulk(data); err != nil {
			return "", xerrors.Errorf("Failed to bulk to table. err: %w", err)
		}
		if err := table.Render(); err != nil {
			return "", xerrors.Errorf("Failed to render table. err: %w", err)
		}

		lines += b.String() + "\n"
	}
	return lines, nil
}

func terminalWidth() int {
	if term.IsTerminal(int(os.Stdout.Fd())) {
		width, _, err := term.GetSize(int(os.Stdout.Fd()))
		if err == nil {
			return width
		}
	}

	if term.IsTerminal(int(os.Stderr.Fd())) {
		width, _, err := term.GetSize(int(os.Stderr.Fd()))
		if err == nil {
			return width
		}
	}

	// Stdout/stderr do not work, fallback to environment variable.
	colsStr := os.Getenv("COLUMNS")
	if colsStr != "" {
		width, err := strconv.Atoi(colsStr)
		if err == nil && width > 0 {
			return width
		}
	}

	return 80
}

func formatCsvList(r models.ScanResult, path string) error {
	data := [][]string{{"CVE-ID", "CVSS", "Attack", "PoC", "CERT", "Fixed", "NVD"}}
	for _, vinfo := range r.ScannedCves.ToSortedSlice() {
		score := vinfo.MaxCvssScore().Value.Score

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
			fmt.Sprintf("%4.1f", score),
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

	newer := models.VulnInfos{}
	updated := models.VulnInfos{}
	for _, v := range current.ScannedCves {
		if previousCveIDsSet[v.CveID] {
			if isCveInfoUpdated(v.CveID, previous, current) {
				v.DiffStatus = models.DiffPlus
				updated[v.CveID] = v
				logging.Log.Debugf("updated: %s", v.CveID)

				// TODO commented out because  a bug of diff logic when multiple oval defs found for a certain CVE-ID and same updated_at
				// if these OVAL defs have different affected packages, this logic detects as updated.
				// This logic will be uncommented after integration with gost https://github.com/vulsio/gost
				// } else if isCveFixed(v, previous) {
				// updated[v.CveID] = v
				// logging.Log.Debugf("fixed: %s", v.CveID)

			} else {
				logging.Log.Debugf("same: %s", v.CveID)
			}
		} else {
			logging.Log.Debugf("newer: %s", v.CveID)
			v.DiffStatus = models.DiffPlus
			newer[v.CveID] = v
		}
	}

	if len(updated) == 0 && len(newer) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	for cveID, vuln := range newer {
		updated[cveID] = vuln
	}
	return updated
}

func getMinusDiffCves(previous, current models.ScanResult) models.VulnInfos {
	currentCveIDsSet := map[string]bool{}
	for _, currentVulnInfo := range current.ScannedCves {
		currentCveIDsSet[currentVulnInfo.CveID] = true
	}

	removed := models.VulnInfos{}
	for _, v := range previous.ScannedCves {
		if !currentCveIDsSet[v.CveID] {
			v.DiffStatus = models.DiffMinus
			removed[v.CveID] = v
			logging.Log.Debugf("clear: %s", v.CveID)
		}
	}
	if len(removed) == 0 {
		logging.Log.Infof("%s: There are %d vulnerabilities, but no difference between current result and previous one.", current.FormatServerName(), len(current.ScannedCves))
	}

	return removed
}

func isCveInfoUpdated(cveID string, previous, current models.ScanResult) bool {
	cTypes := append([]models.CveContentType{models.Mitre, models.Nvd, models.Vulncheck, models.Jvn}, models.GetCveContentTypes(current.Family)...)

	prevLastModifieds := map[models.CveContentType][]time.Time{}
	preVinfo, ok := previous.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if conts, ok := preVinfo.CveContents[cType]; ok {
			for _, cont := range conts {
				prevLastModifieds[cType] = append(prevLastModifieds[cType], cont.LastModified)
			}
		}
	}

	curLastModifieds := map[models.CveContentType][]time.Time{}
	curVinfo, ok := current.ScannedCves[cveID]
	if !ok {
		return true
	}
	for _, cType := range cTypes {
		if conts, ok := curVinfo.CveContents[cType]; ok {
			for _, cont := range conts {
				curLastModifieds[cType] = append(curLastModifieds[cType], cont.LastModified)
			}
		}
	}

	for _, t := range cTypes {
		if !reflect.DeepEqual(curLastModifieds[t], prevLastModifieds[t]) {
			logging.Log.Debugf("%s LastModified not equal: \n%s\n%s",
				cveID, curLastModifieds[t], prevLastModifieds[t])
			return true
		}
	}
	return false
}
