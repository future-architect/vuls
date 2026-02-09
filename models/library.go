package models

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// LibraryScanners is an array of LibraryScanner
type LibraryScanners []LibraryScanner

// Find : find by name
func (lss LibraryScanners) Find(path, name string) map[string]Library {
	filtered := map[string]Library{}
	for _, ls := range lss {
		for _, lib := range ls.Libs {
			if ls.LockfilePath == path && lib.Name == name {
				filtered[ls.LockfilePath] = lib
				break
			}
		}
	}
	return filtered
}

// Total returns total count of pkgs
func (lss LibraryScanners) Total() (total int) {
	for _, lib := range lss {
		total += len(lib.Libs)
	}
	return
}

// LibraryScanner has libraries information
type LibraryScanner struct {
	Type ftypes.LangType
	Libs []Library

	// The path to the Lockfile is stored.
	LockfilePath string `json:"path,omitempty"`
}

// Library holds the attribute of a package library
type Library struct {
	Name    string
	Version string
	PURL    string

	// The Path to the library in the container image. Empty string when Lockfile scan.
	// This field is used to convert the result JSON of a `trivy image` using trivy-to-vuls.
	FilePath string
	Digest   string

	// Dev indicates whether the library is a development dependency.
	Dev bool
}

// FindLockFiles is a list of filenames that is the target of findLock
var FindLockFiles = []string{
	// dart/pub
	ftypes.PubSpecLock,
	// elixir/mix
	ftypes.MixLock,
	// node
	ftypes.NpmPkgLock, ftypes.YarnLock, ftypes.PnpmLock, ftypes.BunLock,
	// ruby
	ftypes.GemfileLock, "*.gemspec",
	// rust
	ftypes.CargoLock,
	// php
	ftypes.ComposerLock, ftypes.ComposerInstalledJson,
	// python
	ftypes.PipRequirements, ftypes.PipfileLock, ftypes.PoetryLock, ftypes.UvLock,
	// .net
	ftypes.NuGetPkgsLock, ftypes.NuGetPkgsConfig, "*.deps.json", "*Packages.props",
	// gomod
	ftypes.GoMod, ftypes.GoSum,
	// java
	ftypes.MavenPom, "*.jar", "*.war", "*.ear", "*.par", "*gradle.lockfile",
	// C / C++
	ftypes.ConanLock,
	// Swift
	ftypes.CocoaPodsLock, ftypes.SwiftResolved,
}

// GetLibraryKey returns target library key
func (s LibraryScanner) GetLibraryKey() string {
	switch s.Type {
	case ftypes.Bundler, ftypes.GemSpec:
		return "ruby"
	case ftypes.Cargo, ftypes.RustBinary:
		return "rust"
	case ftypes.Composer, ftypes.ComposerVendor:
		return "php"
	case ftypes.GoBinary, ftypes.GoModule:
		return "gomod"
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle:
		return "java"
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.NodePkg, ftypes.JavaScript, ftypes.Bun:
		return "node"
	case ftypes.NuGet, ftypes.DotNetCore:
		return ".net"
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Uv, ftypes.Pip, ftypes.PythonPkg:
		return "python"
	case ftypes.Conan:
		return "c"
	case ftypes.Pub:
		return "dart"
	case ftypes.Hex:
		return "elixir"
	case ftypes.Swift, ftypes.Cocoapods:
		return "swift"
	default:
		return ""
	}
}

// LibraryFixedIn has library fixed information
type LibraryFixedIn struct {
	Key     string `json:"key,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	FixedIn string `json:"fixedIn,omitempty"`
	Path    string `json:"path,omitempty"`
}
