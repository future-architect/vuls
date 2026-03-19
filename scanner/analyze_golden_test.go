package scanner

import (
	"cmp"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/future-architect/vuls/models"
)

var update = flag.Bool("update", false, "update golden files")

// lockfileEntry defines a test fixture for AnalyzeLibrary golden testing.
type lockfileEntry struct {
	// path is the relative path from the fixtures directory.
	path string
	// filemode to pass to AnalyzeLibrary (0755 for executables, 0644 otherwise).
	filemode os.FileMode
	// binary indicates the fixture is a binary file only available in the
	// integration submodule (not copied to testdata/fixtures/).
	binary bool
	// expectParseError indicates this fixture is known to produce a parse error
	// (e.g. unsupported lockfile version). The test treats errors as empty result.
	expectParseError bool
}

var lockfiles = []lockfileEntry{
	// Node.js
	{"npm-v1/package-lock.json", 0644, false, false},
	{"npm-v2/package-lock.json", 0644, false, false},
	{"npm-v3/package-lock.json", 0644, false, false},
	{"yarn.lock", 0644, false, false},
	{"pnpm/pnpm-lock.yaml", 0644, false, true}, // pnpm v8: known parse error
	{"pnpm-v9/pnpm-lock.yaml", 0644, false, false},
	{"bun.lock", 0644, false, false},

	// Python
	{"requirements.txt", 0644, false, false},
	{"Pipfile.lock", 0644, false, false},
	{"poetry-v1/poetry.lock", 0644, false, false},
	{"poetry-v2/poetry.lock", 0644, false, false},
	{"uv.lock", 0644, false, false},

	// Ruby
	{"Gemfile.lock", 0644, false, false},

	// Rust
	{"Cargo.lock", 0644, false, false},
	{"hello-rust", 0755, true, false},

	// PHP
	{"composer.lock", 0644, false, false},
	{"installed.json", 0644, false, false},

	// Go
	{"go.mod", 0644, false, false},
	{"go.sum", 0644, false, false},
	{"gobinary", 0755, true, false},

	// Java
	{"pom.xml", 0644, false, false},
	{"gradle.lockfile", 0644, false, false},
	{"log4j-core-2.13.0.jar", 0644, true, false},
	{"wrong-name-log4j-core.jar", 0644, true, false},
	{"juddiv3-war-3.3.5.war", 0644, true, false},

	// .NET
	{"packages.lock.json", 0644, false, false},
	{"packages.config", 0644, false, false},
	{"datacollector.deps.json", 0644, false, false},
	{"Directory.Packages.props", 0644, false, false},

	// C/C++
	{"conan-v1/conan.lock", 0644, false, false},
	{"conan-v2/conan.lock", 0644, false, false},

	// Dart
	{"pubspec.lock", 0644, false, false},

	// Elixir
	{"mix.lock", 0644, false, false},

	// Swift
	{"Podfile.lock", 0644, false, false},
	{"Package.resolved", 0644, false, false},
}

// goldenFileName converts a lockfile path to a golden file name.
// e.g. "npm-v3/package-lock.json" -> "npm-v3_package-lock.json"
// Uses filepath.ToSlash to normalize path separators across platforms.
func goldenFileName(lockfilePath string) string {
	return strings.ReplaceAll(filepath.ToSlash(lockfilePath), "/", "_") + ".golden.json"
}

func TestAnalyzeLibrary_Golden(t *testing.T) {
	fixturesDir := filepath.Join("testdata", "fixtures")
	integrationDir := filepath.Join("..", "integration", "data", "lockfile")
	goldenDir := filepath.Join("testdata", "golden")

	for _, lf := range lockfiles {
		t.Run(lf.path, func(t *testing.T) {
			// Test fixtures are in testdata/fixtures/ (committed to repo).
			// Binary fixtures (JAR, WAR, Go/Rust binaries) are only in the
			// integration submodule — skip if not available.
			// NOTE: We intentionally do NOT add submodules: true to CI checkout.
			// Attack scenario: an attacker forks this repo, edits .gitmodules to
			// replace the integration submodule URL with their own repo containing
			// a malicious go.mod or _test.go, then opens a PR. If CI checks out
			// submodules, `go test` executes attacker-controlled code with access
			// to the CI environment (secrets, GITHUB_TOKEN, network).
			// Binary fixture tests therefore run locally only.
			srcPath := filepath.Join(fixturesDir, lf.path)
			if lf.binary {
				srcPath = filepath.Join(integrationDir, lf.path)
			}
			contents, err := os.ReadFile(srcPath)
			if err != nil {
				if lf.binary {
					t.Skipf("Binary fixture not found: %s (requires: git submodule update --init)", srcPath)
				}
				t.Fatalf("Failed to read %s: %v", srcPath, err)
			}

			got, err := AnalyzeLibrary(context.Background(), lf.path, contents, lf.filemode, true)
			if err != nil {
				if lf.expectParseError {
					// Verify the error is actually a parse error (contains "parse error" or the parser type)
					errMsg := err.Error()
					if !strings.Contains(errMsg, "parse error") && !strings.Contains(errMsg, "Failed to parse") {
						t.Fatalf("AnalyzeLibrary(%s) expected parse error but got: %v", lf.path, err)
					}
					t.Logf("AnalyzeLibrary(%s) returned expected parse error: %v", lf.path, err)
					got = nil
				} else {
					t.Fatalf("AnalyzeLibrary(%s) unexpected error: %v", lf.path, err)
				}
			}

			gotJSON, err := json.MarshalIndent(normalizeResult(got), "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal result: %v", err)
			}

			goldenPath := filepath.Join(goldenDir, goldenFileName(lf.path))

			if *update {
				if err := os.MkdirAll(goldenDir, 0755); err != nil {
					t.Fatalf("Failed to create golden dir: %v", err)
				}
				if err := os.WriteFile(goldenPath, gotJSON, 0644); err != nil {
					t.Fatalf("Failed to write golden file: %v", err)
				}
				t.Logf("Updated golden file: %s", goldenPath)
				return
			}

			wantJSON, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("Golden file not found: %s (run with -update to generate)", goldenPath)
			}

			if string(gotJSON) != string(wantJSON) {
				t.Errorf("AnalyzeLibrary(%s) output differs from golden file.\nGot:\n%s\nWant:\n%s",
					lf.path, string(gotJSON), string(wantJSON))
			}
		})
	}
}

// TestAnalyzeLibrary_PomOnline verifies that pom.xml parsing in online mode
// (resolving transitive dependencies from Maven Central) works correctly.
// Skipped with -short since it requires network access.
func TestAnalyzeLibrary_PomOnline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping online pom.xml test (requires network access)")
	}

	fixturesDir := filepath.Join("testdata", "fixtures")
	goldenDir := filepath.Join("testdata", "golden")

	contents, err := os.ReadFile(filepath.Join(fixturesDir, "pom.xml"))
	if err != nil {
		t.Fatalf("Failed to read pom.xml: %v", err)
	}

	got, err := AnalyzeLibrary(context.Background(), "pom.xml", contents, 0644, false)
	if err != nil {
		t.Fatalf("AnalyzeLibrary(pom.xml, online) unexpected error: %v", err)
	}

	gotJSON, err := json.MarshalIndent(normalizeResult(got), "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal result: %v", err)
	}

	goldenPath := filepath.Join(goldenDir, "pom.xml.online.golden.json")

	if *update {
		if err := os.MkdirAll(goldenDir, 0755); err != nil {
			t.Fatalf("Failed to create golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, gotJSON, 0644); err != nil {
			t.Fatalf("Failed to write golden file: %v", err)
		}
		t.Logf("Updated golden file: %s", goldenPath)
		return
	}

	wantJSON, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("Golden file not found: %s (run with -update to generate)", goldenPath)
	}

	if string(gotJSON) != string(wantJSON) {
		t.Errorf("AnalyzeLibrary(pom.xml, online) output differs from golden file.\nGot:\n%s\nWant:\n%s",
			string(gotJSON), string(wantJSON))
	}

	// Online mode should resolve transitive dependencies, producing more results than offline.
	offlineGoldenPath := filepath.Join(goldenDir, "pom.xml.golden.json")
	offlineJSON, err := os.ReadFile(offlineGoldenPath)
	if err != nil {
		t.Logf("Offline golden file not found, skipping comparison: %s", offlineGoldenPath)
		return
	}
	if len(gotJSON) <= len(offlineJSON) {
		t.Errorf("Online mode should resolve more dependencies than offline mode.\nOnline: %d bytes\nOffline: %d bytes",
			len(gotJSON), len(offlineJSON))
	}
}

// normalizeResult produces a stable, comparable representation of the scan result.
// It sorts libraries by name+version to avoid ordering-dependent diffs.
type goldenLibraryScanner struct {
	Type         string          `json:"type"`
	LockfilePath string          `json:"lockfilePath"`
	Libs         []goldenLibrary `json:"libs"`
}

type goldenLibrary struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	PURL     string `json:"purl,omitempty"`
	FilePath string `json:"filePath,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Dev      bool   `json:"dev,omitempty"`
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func normalizeResult(scanners []models.LibraryScanner) []goldenLibraryScanner {
	result := make([]goldenLibraryScanner, 0, len(scanners))
	for _, s := range scanners {
		gs := goldenLibraryScanner{
			Type:         string(s.Type),
			LockfilePath: s.LockfilePath,
			Libs:         make([]goldenLibrary, 0, len(s.Libs)),
		}
		for _, lib := range s.Libs {
			gs.Libs = append(gs.Libs, goldenLibrary{
				Name:     lib.Name,
				Version:  lib.Version,
				PURL:     lib.PURL,
				FilePath: lib.FilePath,
				Digest:   lib.Digest,
				Dev:      lib.Dev,
			})
		}
		slices.SortFunc(gs.Libs, func(a, b goldenLibrary) int {
			if c := cmp.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			if c := cmp.Compare(a.Version, b.Version); c != 0 {
				return c
			}
			if c := cmp.Compare(a.PURL, b.PURL); c != 0 {
				return c
			}
			if c := cmp.Compare(a.FilePath, b.FilePath); c != 0 {
				return c
			}
			if c := cmp.Compare(a.Digest, b.Digest); c != 0 {
				return c
			}
			return cmp.Compare(boolToInt(a.Dev), boolToInt(b.Dev))
		})
		result = append(result, gs)
	}
	slices.SortFunc(result, func(a, b goldenLibraryScanner) int {
		if c := cmp.Compare(a.Type, b.Type); c != 0 {
			return c
		}
		return cmp.Compare(a.LockfilePath, b.LockfilePath)
	})
	return result
}
