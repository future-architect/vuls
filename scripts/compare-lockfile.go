//go:build ignore

// compare-lockfile.go compares AnalyzeLibrary output between two Git refs.
//
// Usage:
//
//	go run scripts/compare-lockfile.go [flags]
//
// Flags:
//
//	-base string    Base Git ref to compare against (default "master")
//	-fetch          Download lockfile fixtures from the internet
//	-fixtures string Path to lockfile-fixtures.json (default "scripts/lockfile-fixtures.json")
//	-workdir string Working directory for temporary files (default "/tmp/diet-compare")
//	-log string     Path to write detailed log (default "<workdir>/comparison.log")
//
// Examples:
//
//	# Full comparison: fetch fixtures and compare against master
//	go run scripts/compare-analyze.go -fetch -base master
//
//	# Re-run comparison with previously fetched fixtures
//	go run scripts/compare-analyze.go -base master
//
//	# Compare against a specific commit
//	go run scripts/compare-analyze.go -fetch -base abc1234
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/scanner"
)

type fixture struct {
	Type        string      `json:"type"`
	Project     string      `json:"project"`
	Tag         string      `json:"tag"`
	Filename    string      `json:"filename"`
	Filemode    os.FileMode `json:"filemode,omitempty"` // 0 means 0644
	URL         string      `json:"url"`
	ArchivePath string      `json:"archivePath,omitempty"` // path inside tar.gz archive
}

func (f fixture) effectiveFilemode() os.FileMode {
	if f.Filemode != 0 {
		return f.Filemode
	}
	return 0644
}

type lib struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	PURL     string `json:"purl,omitempty"`
	FilePath string `json:"filePath,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Dev      bool   `json:"dev,omitempty"`
}

type result struct {
	Type         string `json:"type"`
	LockfilePath string `json:"lockfilePath"`
	Libs         []lib  `json:"libs"`
}

func normalize(scanners []models.LibraryScanner) []result {
	out := make([]result, 0, len(scanners))
	for _, s := range scanners {
		r := result{Type: string(s.Type), LockfilePath: s.LockfilePath}
		for _, l := range s.Libs {
			r.Libs = append(r.Libs, lib{
				Name: l.Name, Version: l.Version, PURL: l.PURL,
				FilePath: l.FilePath, Digest: l.Digest, Dev: l.Dev,
			})
		}
		slices.SortFunc(r.Libs, func(a, b lib) int {
			if c := cmp.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			return cmp.Compare(a.Version, b.Version)
		})
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b result) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return cmp.Compare(a.LockfilePath, b.LockfilePath)
	})
	return out
}

func countLibs(scanners []models.LibraryScanner) int {
	n := 0
	for _, s := range scanners {
		n += len(s.Libs)
	}
	return n
}

type logger struct {
	file *os.File
}

func newLogger(path string) (*logger, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return &logger{file: f}, nil
}

func (l *logger) log(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Println(msg)
	fmt.Fprintln(l.file, msg)
}

func (l *logger) close() { l.file.Close() }

func main() {
	baseRef := flag.String("base", "master", "Base Git ref to compare against")
	fetch := flag.Bool("fetch", false, "Download lockfile fixtures from the internet")
	fixturesPath := flag.String("fixtures", "scripts/lockfile-fixtures.json", "Path to lockfile-fixtures.json")
	workdir := flag.String("workdir", "/tmp/diet-compare", "Working directory for temporary files")
	logPath := flag.String("log", "", "Path to write detailed log (default: <workdir>/comparison.log)")
	flag.Parse()

	if *logPath == "" {
		*logPath = filepath.Join(*workdir, "comparison.log")
	}

	os.MkdirAll(*workdir, 0755)
	fixtureDir := filepath.Join(*workdir, "fixtures")
	resultCurrentDir := filepath.Join(*workdir, "result-current")
	resultBaseDir := filepath.Join(*workdir, "result-base")
	os.MkdirAll(fixtureDir, 0755)
	os.MkdirAll(resultCurrentDir, 0755)
	os.MkdirAll(resultBaseDir, 0755)

	log, err := newLogger(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create log: %v\n", err)
		os.Exit(1)
	}
	defer log.close()

	log.log("=== compare-analyze.go ===")
	log.log("Date: %s", time.Now().Format(time.RFC3339))
	log.log("Base ref: %s", *baseRef)
	log.log("Workdir: %s", *workdir)
	log.log("")

	// Load fixtures
	fixtures, err := loadFixtures(*fixturesPath)
	if err != nil {
		log.log("ERROR: Failed to load fixtures: %v", err)
		os.Exit(1)
	}
	log.log("Loaded %d fixtures from %s", len(fixtures), *fixturesPath)
	log.log("")

	// Fetch fixtures
	if *fetch {
		log.log("=== Fetching fixtures ===")
		for _, f := range fixtures {
			log.log("# curl -sL -o %s/%s %q", fixtureDir, f.safeFilename(), f.URL)
			if err := fetchFixture(f, fixtureDir); err != nil {
				log.log("FETCH ERROR  %-12s %-40s %v", f.Type, f.Project, err)
			} else {
				info, _ := os.Stat(filepath.Join(fixtureDir, f.safeFilename()))
				log.log("FETCH OK     %-12s %-40s %dB", f.Type, f.Project, info.Size())
			}
		}
		log.log("")
	}

	// Run on current branch
	log.log("=== Running AnalyzeLibrary on current branch ===")
	currentResults := runAnalyze(fixtures, fixtureDir, resultCurrentDir, log)

	// Run on base ref using worktree
	log.log("")
	log.log("=== Running AnalyzeLibrary on %s (via worktree subprocess) ===", *baseRef)
	baseResults := runOnBase(*baseRef, fixtures, fixtureDir, resultBaseDir, *fixturesPath, *workdir, log)

	// Compare
	log.log("")
	log.log("=== Comparison ===")
	identical, different, skipped := 0, 0, 0
	for _, f := range fixtures {
		fname := f.safeFilename() + ".result.json"
		currentFile := filepath.Join(resultCurrentDir, fname)
		baseFile := filepath.Join(resultBaseDir, fname)

		currentJSON, err1 := os.ReadFile(currentFile)
		baseJSON, err2 := os.ReadFile(baseFile)

		if err1 != nil || err2 != nil {
			log.log("SKIP  %-12s %-40s (missing output)", f.Type, f.Project)
			skipped++
			continue
		}

		if string(currentJSON) == string(baseJSON) {
			cLibs := currentResults[f.safeFilename()]
			log.log("IDENTICAL  %-12s %-40s (%d libs)", f.Type, f.Project, cLibs)
			identical++
		} else {
			log.log("DIFFERENT  %-12s %-40s", f.Type, f.Project)
			// Show diff
			cmd := exec.Command("diff", "-u", baseFile, currentFile)
			out, _ := cmd.Output()
			log.log("%s", string(out))
			different++
		}
	}

	log.log("")
	log.log("=== Summary ===")
	log.log("Total: %d fixtures", len(fixtures))
	log.log("Identical: %d", identical)
	log.log("Different: %d", different)
	log.log("Skipped: %d", skipped)
	log.log("")
	log.log("Base results: %s", resultBaseDir)
	log.log("Current results: %s", resultCurrentDir)
	log.log("Log: %s", *logPath)

	_ = baseResults // used via file comparison

	if different > 0 {
		os.Exit(1)
	}
}

func loadFixtures(path string) ([]fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fixtures []fixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		return nil, err
	}
	return fixtures, nil
}

func (f fixture) safeFilename() string {
	return strings.ReplaceAll(f.Project, "/", "_") + "__" + f.Filename
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

func fetchFixture(f fixture, dir string) error {
	resp, err := httpClient.Get(f.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	outPath := filepath.Join(dir, f.safeFilename())

	// Handle tar.gz archives: extract a specific file
	if f.ArchivePath != "" && (strings.HasSuffix(f.URL, ".tar.gz") || strings.HasSuffix(f.URL, ".tgz")) {
		return extractFromTarGz(resp.Body, f.ArchivePath, outPath)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

func extractFromTarGz(r io.Reader, targetPath, outPath string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("gzip open: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("file %q not found in archive", targetPath)
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		if hdr.Name == targetPath {
			out, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer out.Close()
			_, err = io.Copy(out, tr)
			return err
		}
	}
}

func runAnalyze(fixtures []fixture, fixtureDir, outputDir string, log *logger) map[string]int {
	results := make(map[string]int)
	for _, f := range fixtures {
		srcPath := filepath.Join(fixtureDir, f.safeFilename())
		contents, err := os.ReadFile(srcPath)
		if err != nil {
			log.log("READ ERROR  %-12s %-40s %v", f.Type, f.Project, err)
			continue
		}

		got, err := scanner.AnalyzeLibrary(context.Background(), f.Filename, contents, f.effectiveFilemode(), true)
		if err != nil {
			log.log("PARSE ERROR %-12s %-40s %v", f.Type, f.Project, err)
			// Still write empty result for comparison
			got = nil
		}

		j, _ := json.MarshalIndent(normalize(got), "", "  ")
		outFile := filepath.Join(outputDir, f.safeFilename()+".result.json")
		os.WriteFile(outFile, j, 0644)

		libs := countLibs(got)
		results[f.safeFilename()] = libs
		log.log("OK  %-12s %-40s %d libs", f.Type, f.Project, libs)
	}
	return results
}

func runOnBase(baseRef string, fixtures []fixture, fixtureDir, outputDir, fixturesPath, workdir string, log *logger) map[string]int {
	// Create worktree
	worktreeDir := filepath.Join(workdir, "worktree-"+baseRef)
	os.RemoveAll(worktreeDir)

	cmd := exec.Command("git", "worktree", "add", worktreeDir, baseRef)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.log("ERROR: Failed to create worktree: %v\n%s", err, out)
		return nil
	}
	defer func() {
		exec.Command("git", "worktree", "remove", "--force", worktreeDir).Run()
	}()

	log.log("Created worktree at %s for %s", worktreeDir, baseRef)

	// Copy this script and fixtures to worktree
	copyFile(fixturesPath, filepath.Join(worktreeDir, "scripts", "lockfile-fixtures.json"))

	// Write a minimal runner that uses the base's scanner package
	runnerCode := `//go:build ignore

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/scanner"
)

type fixture struct {
	Type     string      ` + "`json:\"type\"`" + `
	Project  string      ` + "`json:\"project\"`" + `
	Filename string      ` + "`json:\"filename\"`" + `
	Filemode os.FileMode ` + "`json:\"filemode,omitempty\"`" + `
	URL      string      ` + "`json:\"url\"`" + `
}

func (f fixture) effectiveFilemode() os.FileMode {
	if f.Filemode != 0 { return f.Filemode }
	return 0644
}

type lib struct {
	Name     string ` + "`json:\"name\"`" + `
	Version  string ` + "`json:\"version\"`" + `
	PURL     string ` + "`json:\"purl,omitempty\"`" + `
	FilePath string ` + "`json:\"filePath,omitempty\"`" + `
	Digest   string ` + "`json:\"digest,omitempty\"`" + `
	Dev      bool   ` + "`json:\"dev,omitempty\"`" + `
}

type result struct {
	Type         string ` + "`json:\"type\"`" + `
	LockfilePath string ` + "`json:\"lockfilePath\"`" + `
	Libs         []lib  ` + "`json:\"libs\"`" + `
}

func normalize(scanners []models.LibraryScanner) []result {
	out := make([]result, 0, len(scanners))
	for _, s := range scanners {
		r := result{Type: string(s.Type), LockfilePath: s.LockfilePath}
		for _, l := range s.Libs {
			r.Libs = append(r.Libs, lib{
				Name: l.Name, Version: l.Version, PURL: l.PURL,
				FilePath: l.FilePath, Digest: l.Digest, Dev: l.Dev,
			})
		}
		slices.SortFunc(r.Libs, func(a, b lib) int {
			if c := cmp.Compare(a.Name, b.Name); c != 0 { return c }
			return cmp.Compare(a.Version, b.Version)
		})
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b result) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 { return c }
		return cmp.Compare(a.LockfilePath, b.LockfilePath)
	})
	return out
}

func main() {
	fixtureDir := os.Args[1]
	outputDir := os.Args[2]
	fixturesJSON := os.Args[3]
	os.MkdirAll(outputDir, 0755)

	data, _ := os.ReadFile(fixturesJSON)
	var fixtures []fixture
	json.Unmarshal(data, &fixtures)

	for _, f := range fixtures {
		safe := replaceAll(f.Project, "/", "_") + "__" + f.Filename

		srcPath := filepath.Join(fixtureDir, safe)
		contents, err := os.ReadFile(srcPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "READ ERROR  %-12s %-40s %v\n", f.Type, f.Project, err)
			continue
		}

		got, err := scanner.AnalyzeLibrary(context.Background(), f.Filename, contents, f.effectiveFilemode(), true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PARSE ERROR %-12s %-40s %v\n", f.Type, f.Project, err)
			got = nil
		}

		j, _ := json.MarshalIndent(normalize(got), "", "  ")
		outFile := filepath.Join(outputDir, safe+".result.json")
		os.WriteFile(outFile, j, 0644)
		libs := 0
		for _, s := range got { libs += len(s.Libs) }
		fmt.Printf("OK  %-12s %-40s %d libs\n", f.Type, f.Project, libs)
	}
}

func replaceAll(s, old, new string) string {
	for {
		i := indexOf(s, old)
		if i < 0 { return s }
		s = s[:i] + new + s[i+len(old):]
	}
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub { return i }
	}
	return -1
}
`
	os.MkdirAll(filepath.Join(worktreeDir, "scripts"), 0755)
	os.WriteFile(filepath.Join(worktreeDir, "base_runner.go"), []byte(runnerCode), 0644)

	// Run the base runner in worktree
	cmd = exec.Command("go", "run", "base_runner.go", fixtureDir, outputDir,
		filepath.Join(worktreeDir, "scripts", "lockfile-fixtures.json"))
	cmd.Dir = worktreeDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.log("ERROR: Failed to run base analysis: %v", err)
		return nil
	}

	// Count results
	results := make(map[string]int)
	entries, _ := os.ReadDir(outputDir)
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(outputDir, e.Name()))
		var res []result
		json.Unmarshal(data, &res)
		libs := 0
		for _, r := range res {
			libs += len(r.Libs)
		}
		results[strings.TrimSuffix(e.Name(), ".json")] = libs
	}
	return results
}

func copyFile(src, dst string) error {
	os.MkdirAll(filepath.Dir(dst), 0755)
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
