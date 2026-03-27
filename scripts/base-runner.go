//go:build ignore

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/scanner"
)

type fixture struct {
	Type     string      `json:"type"`
	Project  string      `json:"project"`
	Filename string      `json:"filename"`
	Filemode os.FileMode `json:"filemode,omitempty"`
	URL      string      `json:"url"`
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
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b result) int {
		return cmp.Or(
			cmp.Compare(a.Type, b.Type),
			cmp.Compare(a.LockfilePath, b.LockfilePath),
		)
	})
	return out
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: %s <fixtureDir> <outputDir> <fixturesJSON>\n", os.Args[0])
		os.Exit(1)
	}
	fixtureDir := os.Args[1]
	outputDir := os.Args[2]
	fixturesJSON := os.Args[3]
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create output dir: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(fixturesJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read fixtures: %v\n", err)
		os.Exit(1)
	}
	var fixtures []fixture
	if err := json.Unmarshal(data, &fixtures); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse fixtures: %v\n", err)
		os.Exit(1)
	}

	replacer := strings.NewReplacer("/", "_", "\\", "_", "..", "_")
	for _, f := range fixtures {
		safe := replacer.Replace(f.Project) + "__" + replacer.Replace(f.Filename)

		srcPath := filepath.Join(fixtureDir, safe)
		contents, err := os.ReadFile(srcPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "READ ERROR  %-12s %-40s %v\n", f.Type, f.Project, err)
			continue
		}

		parseErr := false
		got, err := scanner.AnalyzeLibrary(context.Background(), f.Filename, contents, f.effectiveFilemode(), true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "PARSE ERROR %-12s %-40s %v\n", f.Type, f.Project, err)
			got = nil
			parseErr = true
		}

		j, jerr := json.MarshalIndent(normalize(got), "", "  ")
		if jerr != nil {
			fmt.Fprintf(os.Stderr, "JSON ERROR  %-12s %-40s %v\n", f.Type, f.Project, jerr)
			continue
		}
		outFile := filepath.Join(outputDir, safe+".result.json")
		if werr := os.WriteFile(outFile, j, 0644); werr != nil {
			fmt.Fprintf(os.Stderr, "WRITE ERROR %-12s %-40s %v\n", f.Type, f.Project, werr)
			continue
		}
		libs := 0
		for _, s := range got {
			libs += len(s.Libs)
		}
		if parseErr {
			fmt.Fprintf(os.Stderr, "PARSE ERROR %-12s %-40s (wrote empty result)\n", f.Type, f.Project)
		} else {
			fmt.Printf("OK  %-12s %-40s %d libs\n", f.Type, f.Project, libs)
		}
	}
}
