package scanner

import (
	"os"
	"path/filepath"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// parserType represents the type of parser to use for a given file.
// Empty string means the file is not a recognized lockfile/artifact.
type parserType string

const (
	parserNone           parserType = ""
	parserNpm            parserType = "npm"
	parserYarn           parserType = "yarn"
	parserPnpm           parserType = "pnpm"
	parserBun            parserType = "bun"
	parserPip            parserType = "pip"
	parserPipenv         parserType = "pipenv"
	parserPoetry         parserType = "poetry"
	parserUv             parserType = "uv"
	parserBundler        parserType = "bundler"
	parserCargo          parserType = "cargo"
	parserComposer       parserType = "composer"
	parserGoMod          parserType = "gomod"
	parserGoBinary       parserType = "gobinary"
	parserPom            parserType = "pom"
	parserGradle         parserType = "gradle"
	parserJar            parserType = "jar"
	parserNugetLock      parserType = "nuget-lock"
	parserNugetConfig    parserType = "nuget-config"
	parserDotnetDeps     parserType = "dotnet-deps"
	parserPackagesProps  parserType = "packages-props"
	parserConan          parserType = "conan"
	parserPub            parserType = "pub"
	parserMix            parserType = "mix"
	parserCocoapods      parserType = "cocoapods"
	parserSwift          parserType = "swift"
	parserRustBinary     parserType = "rust-binary"
)

// detectParserType determines which parser should handle a given file,
// replicating the logic of each Trivy fanal analyzer's Required() method.
func detectParserType(filePath string, filemode os.FileMode) parserType {
	fileName := filepath.Base(filePath)

	// Exact filename matches (most common case)
	switch fileName {
	// Node.js
	case ftypes.NpmPkgLock: // package-lock.json
		if containsDir(filePath, "node_modules") {
			return parserNone
		}
		return parserNpm
	case ftypes.YarnLock: // yarn.lock
		if containsDir(filePath, "node_modules") || containsDir(filePath, ".yarn") {
			return parserNone
		}
		return parserYarn
	case ftypes.PnpmLock: // pnpm-lock.yaml
		if containsDir(filePath, "node_modules") {
			return parserNone
		}
		return parserPnpm
	case ftypes.BunLock: // bun.lock
		return parserBun

	// Python
	case ftypes.PipRequirements: // requirements.txt
		return parserPip
	case ftypes.PipfileLock: // Pipfile.lock
		return parserPipenv
	case ftypes.PoetryLock: // poetry.lock
		return parserPoetry
	case ftypes.UvLock: // uv.lock
		return parserUv

	// Ruby
	case ftypes.GemfileLock: // Gemfile.lock
		return parserBundler

	// Rust
	case ftypes.CargoLock: // Cargo.lock
		return parserCargo

	// PHP
	case ftypes.ComposerLock: // composer.lock
		return parserComposer

	// Go
	case ftypes.GoMod: // go.mod
		return parserGoMod
	case ftypes.GoSum: // go.sum
		// go.sum is processed as a supplement to go.mod in Trivy's fanal framework.
		// When passed standalone, it returns no results. Match that behavior.
		return parserNone

	// Java
	case ftypes.MavenPom: // pom.xml
		return parserPom

	// .NET
	case ftypes.NuGetPkgsLock: // packages.lock.json
		return parserNugetLock
	case ftypes.NuGetPkgsConfig: // packages.config
		return parserNugetConfig

	// C/C++
	case ftypes.ConanLock: // conan.lock
		return parserConan

	// Dart
	case ftypes.PubSpecLock: // pubspec.lock
		return parserPub

	// Elixir
	case ftypes.MixLock: // mix.lock
		return parserMix

	// Swift
	case ftypes.CocoaPodsLock: // Podfile.lock
		return parserCocoapods
	case ftypes.SwiftResolved: // Package.resolved
		return parserSwift
	}

	// Suffix-based matches
	if strings.HasSuffix(filePath, ".deps.json") {
		return parserDotnetDeps
	}
	if strings.HasSuffix(strings.ToLower(filePath), "packages.props") {
		return parserPackagesProps
	}
	if strings.HasSuffix(filePath, "gradle.lockfile") {
		return parserGradle
	}

	// Extension-based matches (JAR/WAR/EAR/PAR)
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".jar", ".war", ".ear", ".par":
		return parserJar
	}

	// Executable binary detection (Go binary, Rust binary)
	if isExecutable(filemode) {
		// Both Go and Rust binaries are detected by executable filemode.
		// The actual distinction happens during parsing, not dispatch.
		return parserGoBinary
	}

	return parserNone
}

// containsDir checks if a filepath contains a specific directory component.
func containsDir(filePath, dir string) bool {
	for _, part := range strings.Split(filepath.ToSlash(filePath), "/") {
		if part == dir {
			return true
		}
	}
	return false
}

// isExecutable checks if the file mode indicates an executable file.
func isExecutable(mode os.FileMode) bool {
	return mode&0111 != 0
}
