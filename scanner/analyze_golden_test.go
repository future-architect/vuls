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

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/c/conan"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dart/pub"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/deps"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/nuget"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/dotnet/packagesprops"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/elixir/mix"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/binary"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/golang/mod"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/gradle"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/bun"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/npm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pnpm"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/yarn"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/php/composer"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pip"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/pipenv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/poetry"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/python/uv"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/ruby/bundler"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/rust/cargo"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/swift/cocoapods"
	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/swift/swift"
	_ "github.com/future-architect/vuls/scanner/trivy/jar"

	"github.com/future-architect/vuls/models"
)

var update = flag.Bool("update", false, "update golden files")

// lockfileEntry defines a test fixture for AnalyzeLibrary golden testing.
type lockfileEntry struct {
	// path is the relative path from the integration data directory.
	path string
	// filemode to pass to AnalyzeLibrary (0755 for executables, 0644 otherwise).
	filemode os.FileMode
}

var lockfiles = []lockfileEntry{
	// Node.js
	{"npm-v1/package-lock.json", 0644},
	{"npm-v2/package-lock.json", 0644},
	{"npm-v3/package-lock.json", 0644},
	{"yarn.lock", 0644},
	{"pnpm/pnpm-lock.yaml", 0644},
	{"pnpm-v9/pnpm-lock.yaml", 0644},
	{"bun.lock", 0644},

	// Python
	{"requirements.txt", 0644},
	{"Pipfile.lock", 0644},
	{"poetry-v1/poetry.lock", 0644},
	{"poetry-v2/poetry.lock", 0644},
	{"uv.lock", 0644},

	// Ruby
	{"Gemfile.lock", 0644},

	// Rust
	{"Cargo.lock", 0644},
	{"hello-rust", 0755},

	// PHP
	{"composer.lock", 0644},

	// Go
	{"go.mod", 0644},
	{"go.sum", 0644},
	{"gobinary", 0755},

	// Java
	{"pom.xml", 0644},
	{"gradle.lockfile", 0644},
	{"log4j-core-2.13.0.jar", 0644},
	{"wrong-name-log4j-core.jar", 0644},
	{"juddiv3-war-3.3.5.war", 0644},

	// .NET
	{"packages.lock.json", 0644},
	{"packages.config", 0644},
	{"datacollector.deps.json", 0644},
	{"Directory.Packages.props", 0644},

	// C/C++
	{"conan-v1/conan.lock", 0644},
	{"conan-v2/conan.lock", 0644},

	// Dart
	{"pubspec.lock", 0644},

	// Elixir
	{"mix.lock", 0644},

	// Swift
	{"Podfile.lock", 0644},
	{"Package.resolved", 0644},
}

// goldenFileName converts a lockfile path to a golden file name.
// e.g. "npm-v3/package-lock.json" -> "npm-v3_package-lock.json"
func goldenFileName(lockfilePath string) string {
	return strings.ReplaceAll(lockfilePath, string(os.PathSeparator), "_") + ".golden.json"
}

func TestAnalyzeLibrary_Golden(t *testing.T) {
	integrationDir := filepath.Join("..", "integration", "data", "lockfile")
	goldenDir := filepath.Join("testdata", "golden")

	for _, lf := range lockfiles {
		t.Run(lf.path, func(t *testing.T) {
			srcPath := filepath.Join(integrationDir, lf.path)
			contents, err := os.ReadFile(srcPath)
			if err != nil {
				t.Fatalf("Failed to read %s: %v", srcPath, err)
			}

			got, err := AnalyzeLibrary(context.Background(), lf.path, contents, lf.filemode, true)
			if err != nil {
				t.Fatalf("AnalyzeLibrary(%s) error: %v", lf.path, err)
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
			if c := cmp.Compare(a.Name, b.Name); c != 0 {
				return c
			}
			return cmp.Compare(a.Version, b.Version)
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
