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
	// path is the relative path from integration/data/lockfile/.
	path string
	// filemode to pass to AnalyzeLibrary (0755 for executables, 0644 otherwise).
	filemode os.FileMode
	// expectParseError indicates this fixture is known to produce a parse error
	// (e.g. unsupported lockfile version). The test treats errors as empty result.
	expectParseError bool
}

var lockfiles = []lockfileEntry{
	// Node.js
	{"npm-v1/package-lock.json", 0644, false},
	{"npm-v2/package-lock.json", 0644, false},
	{"npm-v3/package-lock.json", 0644, false},
	{"yarn.lock", 0644, false},
	{"pnpm/pnpm-lock.yaml", 0644, true}, // pnpm v8: known parse error
	{"pnpm-v9/pnpm-lock.yaml", 0644, false},
	{"bun.lock", 0644, false},

	// Python
	{"requirements.txt", 0644, false},
	{"Pipfile.lock", 0644, false},
	{"poetry-v1/poetry.lock", 0644, false},
	{"poetry-v2/poetry.lock", 0644, false},
	{"uv.lock", 0644, false},

	// Ruby
	{"Gemfile.lock", 0644, false},

	// Rust
	{"Cargo.lock", 0644, false},
	{"hello-rust", 0755, false},

	// PHP
	{"composer.lock", 0644, false},
	{"installed-pear/installed.json", 0644, false},
	{"installed-packagist/installed.json", 0644, false},

	// Go
	{"go.mod", 0644, false},
	{"go.sum", 0644, false},
	{"gobinary", 0755, false},

	// Java
	{"pom.xml", 0644, false},
	{"gradle.lockfile", 0644, false},
	{"log4j-core-2.13.0.jar", 0644, false},
	{"wrong-name-log4j-core.jar", 0644, false},
	{"juddiv3-war-3.3.5.war", 0644, false},

	// .NET
	{"packages.lock.json", 0644, false},
	{"packages.config", 0644, false},
	{"datacollector.deps.json", 0644, false},
	{"Directory.Packages.props", 0644, false},

	// C/C++
	{"conan-v1/conan.lock", 0644, false},
	{"conan-v2/conan.lock", 0644, false},

	// Dart
	{"pubspec.lock", 0644, false},

	// Elixir
	{"mix.lock", 0644, false},

	// Swift
	{"Podfile.lock", 0644, false},
	{"Package.resolved", 0644, false},
}

// goldenFileName converts a lockfile path to a golden file name.
// e.g. "npm-v3/package-lock.json" -> "npm-v3_package-lock.json.json"
// Uses filepath.ToSlash to normalize path separators across platforms.
func goldenFileName(lockfilePath string) string {
	return strings.ReplaceAll(filepath.ToSlash(lockfilePath), "/", "_") + ".json"
}

func TestAnalyzeLibrary_Golden(t *testing.T) {
	// All lockfile fixtures live in the vulsio/integration repo at
	// data/lockfile/. Locally that's the integration submodule; in CI it's
	// fetched separately by actions/checkout (repository: vulsio/integration,
	// ref pinned to a commit SHA) — never via submodules: true.
	//
	// We intentionally avoid `submodules: true` on the main checkout because a
	// fork PR could edit .gitmodules to point at a malicious URL containing a
	// crafted go.mod or _test.go; with submodules: true, `go test` would run
	// attacker-controlled code in the CI runner. The separate checkout step
	// pins the upstream repo by commit SHA in the workflow file, which a PR
	// cannot redirect without modifying the workflow itself (and that change
	// is reviewable in the diff).
	lockfileDir := filepath.Join("..", "integration", "data", "lockfile")
	goldenDir := filepath.Join("testdata", "golden")

	if _, err := os.Stat(lockfileDir); err != nil {
		t.Fatalf("integration test data not available at %s (run: git submodule update --init, or check the CI integration checkout step): %v", lockfileDir, err)
	}

	for _, lf := range lockfiles {
		t.Run(lf.path, func(t *testing.T) {
			srcPath := filepath.Join(lockfileDir, lf.path)
			contents, err := os.ReadFile(srcPath)
			if err != nil {
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

	lockfileDir := filepath.Join("..", "integration", "data", "lockfile")
	goldenDir := filepath.Join("testdata", "golden")

	if _, err := os.Stat(lockfileDir); err != nil {
		t.Fatalf("integration test data not available at %s (run: git submodule update --init, or check the CI integration checkout step): %v", lockfileDir, err)
	}

	contents, err := os.ReadFile(filepath.Join(lockfileDir, "pom.xml"))
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

	goldenPath := filepath.Join(goldenDir, "pom.xml.online.json")

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
	offlineGoldenPath := filepath.Join(goldenDir, "pom.xml.json")
	offlineJSON, err := os.ReadFile(offlineGoldenPath)
	if err != nil {
		t.Logf("Offline golden file not found, skipping comparison: %s", offlineGoldenPath)
		return
	}

	var onlineRes []goldenLibraryScanner
	if err := json.Unmarshal(gotJSON, &onlineRes); err != nil {
		t.Fatalf("Failed to unmarshal online JSON result: %v", err)
	}
	var offlineRes []goldenLibraryScanner
	if err := json.Unmarshal(offlineJSON, &offlineRes); err != nil {
		t.Fatalf("Failed to unmarshal offline golden JSON: %v", err)
	}
	var onlineLibs, offlineLibs int
	for _, s := range onlineRes {
		onlineLibs += len(s.Libs)
	}
	for _, s := range offlineRes {
		offlineLibs += len(s.Libs)
	}
	if onlineLibs <= offlineLibs {
		t.Errorf("Online mode should resolve more dependencies than offline mode.\nOnline libs: %d\nOffline libs: %d",
			onlineLibs, offlineLibs)
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
			return cmp.Or(
				cmp.Compare(a.Name, b.Name),
				cmp.Compare(a.Version, b.Version),
				cmp.Compare(a.PURL, b.PURL),
				cmp.Compare(a.FilePath, b.FilePath),
				cmp.Compare(a.Digest, b.Digest),
				func() int {
					switch {
					case !a.Dev && b.Dev:
						return -1
					case a.Dev && !b.Dev:
						return +1
					default:
						return 0
					}
				}(),
			)
		})
		result = append(result, gs)
	}
	slices.SortFunc(result, func(a, b goldenLibraryScanner) int {
		return cmp.Or(
			cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.LockfilePath, b.LockfilePath),
		)
	})
	return result
}
