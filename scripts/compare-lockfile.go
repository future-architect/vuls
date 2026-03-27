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
//	-workdir string Working directory for temporary files (default: os.TempDir()/diet-compare)
//	-log string     Path to write detailed log (default "<workdir>/comparison.log")
//
// Examples:
//
//	# Full comparison: fetch fixtures and compare against master
//	go run scripts/compare-lockfile.go -fetch -base master
//
//	# Re-run comparison with previously fetched fixtures
//	go run scripts/compare-lockfile.go -base master
//
//	# Compare against a specific commit
//	go run scripts/compare-lockfile.go -fetch -base abc1234
package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed base-runner.go
var baseRunnerCode string

type fixture struct {
	Type        string      `json:"type"`
	Project     string      `json:"project"`
	Tag         string      `json:"tag"`
	Filename    string      `json:"filename"`
	Filemode    os.FileMode `json:"filemode,omitempty"` // 0 means 0644
	URL         string      `json:"url"`
	ArchivePath string      `json:"archivePath,omitempty"` // path inside tar.gz archive
}

type logger struct {
	file *os.File
}

func newLogger(path string) (*logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create log directory: %w", err)
	}
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

func (l *logger) close() error { return l.file.Close() }

func main() {
	baseRef := flag.String("base", "master", "Base Git ref to compare against")
	fetch := flag.Bool("fetch", false, "Download lockfile fixtures from the internet")
	fixturesPath := flag.String("fixtures", "scripts/lockfile-fixtures.json", "Path to lockfile-fixtures.json")
	workdir := flag.String("workdir", filepath.Join(os.TempDir(), "diet-compare"), "Working directory for temporary files")
	logPath := flag.String("log", "", "Path to write detailed log (default: <workdir>/comparison.log)")
	flag.Parse()

	if *logPath == "" {
		*logPath = filepath.Join(*workdir, "comparison.log")
	}

	for _, dir := range []string{
		*workdir,
		filepath.Join(*workdir, "fixtures"),
		filepath.Join(*workdir, "result-current"),
		filepath.Join(*workdir, "result-base"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create directory %s: %v\n", dir, err)
			os.Exit(1)
		}
	}
	fixtureDir := filepath.Join(*workdir, "fixtures")
	resultCurrentDir := filepath.Join(*workdir, "result-current")
	resultBaseDir := filepath.Join(*workdir, "result-base")

	log, err := newLogger(*logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create log: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := log.close(); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Failed to close log file: %v\n", err)
		}
	}()

	log.log("=== compare-lockfile.go ===")
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
			if err := fetchFixture(context.Background(), f, fixtureDir); err != nil {
				log.log("FETCH ERROR  %-12s %-40s %v", f.Type, f.Project, err)
			} else if info, err := os.Stat(filepath.Join(fixtureDir, f.safeFilename())); err != nil {
				log.log("FETCH ERROR  %-12s %-40s file not found after download: %v", f.Type, f.Project, err)
			} else {
				log.log("FETCH OK     %-12s %-40s %dB", f.Type, f.Project, info.Size())
			}
		}
		log.log("")
	}

	// Run on current branch
	log.log("=== Running AnalyzeLibrary on current branch ===")
	runAnalyze(fixtureDir, resultCurrentDir, *fixturesPath, log)
	currentResults := countResultLibs(resultCurrentDir)

	// Run on base ref using worktree
	log.log("")
	log.log("=== Running AnalyzeLibrary on %s (via worktree subprocess) ===", *baseRef)
	baseResults := runOnBase(*baseRef, fixtureDir, resultBaseDir, *fixturesPath, *workdir, log)

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
			showDiff(log, baseFile, currentFile)
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

	if different > 0 || skipped > 0 || identical == 0 {
		if skipped > 0 {
			log.log("ERROR: %d fixtures skipped (base-side analysis may have failed)", skipped)
		}
		if identical == 0 {
			log.log("ERROR: no successful comparisons were made")
		}
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

var pathSanitizer = strings.NewReplacer("/", "_", "\\", "_", "..", "_")

func (f fixture) safeFilename() string {
	return pathSanitizer.Replace(f.Project) + "__" + pathSanitizer.Replace(f.Filename)
}

var httpClient = &http.Client{Timeout: 5 * time.Minute}

func fetchFixture(ctx context.Context, f fixture, dir string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d %s", resp.StatusCode, resp.Status)
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
	if _, err := io.Copy(out, resp.Body); err != nil {
		out.Close()
		return err
	}
	return out.Close()
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
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
	}
}

func runAnalyze(fixtureDir, outputDir, fixturesPath string, log *logger) {
	cmd := exec.Command("go", "run", "scripts/base-runner.go", fixtureDir, outputDir, fixturesPath)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log.log("%s", strings.TrimRight(string(out), "\n"))
	}
	if err != nil {
		log.log("ERROR: Failed to run current branch analysis: %v", err)
	}
}

func countResultLibs(outputDir string) map[string]int {
	results := make(map[string]int)
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return results
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".result.json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(outputDir, e.Name()))
		if err != nil {
			continue
		}
		var res []struct {
			Libs []json.RawMessage `json:"libs"`
		}
		if err := json.Unmarshal(data, &res); err != nil {
			continue
		}
		libs := 0
		for _, r := range res {
			libs += len(r.Libs)
		}
		results[strings.TrimSuffix(e.Name(), ".result.json")] = libs
	}
	return results
}

func runOnBase(baseRef, fixtureDir, outputDir, fixturesPath, workdir string, log *logger) map[string]int {
	// Create worktree in a temp directory under workdir to avoid path traversal risks
	worktreeDir, err := os.MkdirTemp(workdir, "worktree-")
	if err != nil {
		log.log("ERROR: Failed to create temp dir for worktree: %v", err)
		return nil
	}
	// MkdirTemp creates the directory, but git worktree add requires it not to exist
	if err := os.Remove(worktreeDir); err != nil {
		log.log("ERROR: Failed to remove temp dir for worktree: %v", err)
		return nil
	}

	cmd := exec.Command("git", "worktree", "add", worktreeDir, baseRef)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.log("ERROR: Failed to create worktree: %v\n%s", err, out)
		return nil
	}
	defer func() {
		if err := exec.Command("git", "worktree", "remove", "--force", worktreeDir).Run(); err != nil {
			log.log("WARNING: Failed to remove worktree %s: %v", worktreeDir, err)
		}
	}()

	log.log("Created worktree at %s for %s", worktreeDir, baseRef)

	// Copy this script and fixtures to worktree
	if err := copyFile(fixturesPath, filepath.Join(worktreeDir, "scripts", "lockfile-fixtures.json")); err != nil {
		log.log("ERROR: Failed to copy fixtures to worktree: %v", err)
		return nil
	}

	if err := os.MkdirAll(filepath.Join(worktreeDir, "scripts"), 0755); err != nil {
		log.log("ERROR: Failed to create scripts dir in worktree: %v", err)
		return nil
	}
	if err := os.WriteFile(filepath.Join(worktreeDir, "base_runner.go"), []byte(baseRunnerCode), 0644); err != nil {
		log.log("ERROR: Failed to write base_runner.go: %v", err)
		return nil
	}

	// Run the base runner in worktree
	cmd = exec.Command("go", "run", "base_runner.go", fixtureDir, outputDir,
		filepath.Join(worktreeDir, "scripts", "lockfile-fixtures.json"))
	cmd.Dir = worktreeDir
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		log.log("%s", strings.TrimRight(string(out), "\n"))
	}
	if err != nil {
		log.log("ERROR: Failed to run base analysis: %v", err)
		return nil
	}

	return countResultLibs(outputDir)
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// showDiff prints a unified-style diff between two files using the external
// diff command if available, falling back to printing file paths.
func showDiff(log *logger, baseFile, currentFile string) {
	diffPath, err := exec.LookPath("diff")
	if err != nil {
		log.log("  (diff command not available; compare manually)")
		log.log("  base:    %s", baseFile)
		log.log("  current: %s", currentFile)
		return
	}
	cmd := exec.Command(diffPath, "-u", baseFile, currentFile)
	out, err := cmd.Output()
	if err != nil {
		// ExitError with exit code 1 is normal for diff (files differ).
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			// expected: files differ
		} else {
			log.log("WARNING: diff command failed: %v", err)
		}
	}
	log.log("%s", string(out))
}
