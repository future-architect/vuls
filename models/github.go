package models

import (
	"fmt"
	"strings"
)

// DependencyGraphManifests has a map of DependencyGraphManifest
// key: BlobPath
type DependencyGraphManifests map[string]DependencyGraphManifest

// DependencyGraphManifest has filename, repository, dependencies
type DependencyGraphManifest struct {
	BlobPath     string       `json:"blobPath"`
	Filename     string       `json:"filename"`
	Repository   string       `json:"repository"`
	Dependencies []Dependency `json:"dependencies"`
}

// RepoURLFilename should be same format with GitHubSecurityAlert.RepoURLManifestPath()
func (m DependencyGraphManifest) RepoURLFilename() string {
	return fmt.Sprintf("%s/%s", m.Repository, m.Filename)
}

// Ecosystem returns a name of ecosystem(or package manager) of manifest(lock) file in trivy way
// https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems
func (m DependencyGraphManifest) Ecosystem() string {
	switch {
	case strings.HasSuffix(m.Filename, "Cargo.lock"),
		strings.HasSuffix(m.Filename, "Cargo.toml"):
		return "cargo" // Rust
	case strings.HasSuffix(m.Filename, "composer.lock"),
		strings.HasSuffix(m.Filename, "composer.json"):
		return "composer" // PHP
	case strings.HasSuffix(m.Filename, ".csproj"),
		strings.HasSuffix(m.Filename, ".vbproj"),
		strings.HasSuffix(m.Filename, ".nuspec"),
		strings.HasSuffix(m.Filename, ".vcxproj"),
		strings.HasSuffix(m.Filename, ".fsproj"),
		strings.HasSuffix(m.Filename, "packages.config"):
		return "nuget" // .NET languages (C#, F#, VB), C++
	case strings.HasSuffix(m.Filename, "go.sum"),
		strings.HasSuffix(m.Filename, "go.mod"):
		return "gomod" // Go
	case strings.HasSuffix(m.Filename, "pom.xml"):
		return "pom" // Java, Scala
	case strings.HasSuffix(m.Filename, "package-lock.json"),
		strings.HasSuffix(m.Filename, "package.json"):
		return "npm" // JavaScript
	case strings.HasSuffix(m.Filename, "yarn.lock"):
		return "yarn" // JavaScript
	case strings.HasSuffix(m.Filename, "pnpm-lock.yaml"):
		return "pnpm" // JavaScript
	case strings.HasSuffix(m.Filename, "requirements.txt"),
		strings.HasSuffix(m.Filename, "requirements-dev.txt"),
		strings.HasSuffix(m.Filename, "setup.py"):
		return "pip" // Python
	case strings.HasSuffix(m.Filename, "Pipfile.lock"),
		strings.HasSuffix(m.Filename, "Pipfile"):
		return "pipenv" // Python
	case strings.HasSuffix(m.Filename, "poetry.lock"),
		strings.HasSuffix(m.Filename, "pyproject.toml"):
		return "poetry" // Python
	case strings.HasSuffix(m.Filename, "Gemfile.lock"),
		strings.HasSuffix(m.Filename, "Gemfile"):
		return "bundler" // Ruby
	case strings.HasSuffix(m.Filename, ".gemspec"):
		return "gemspec" // Ruby
	case strings.HasSuffix(m.Filename, "pubspec.lock"),
		strings.HasSuffix(m.Filename, "pubspec.yaml"):
		return "pub" // Dart
	case strings.HasSuffix(m.Filename, "Package.resolved"):
		return "swift" // Swift
	case strings.HasSuffix(m.Filename, ".yml"),
		strings.HasSuffix(m.Filename, ".yaml"):
		return "actions" // GitHub Actions workflows
	default:
		return "unknown"
	}
}

// Dependency has dependency package information
type Dependency struct {
	PackageName    string `json:"packageName"`
	PackageManager string `json:"packageManager"`
	Repository     string `json:"repository"`
	Requirements   string `json:"requirements"`
}

// Version returns version
func (d Dependency) Version() string {
	s := strings.Split(d.Requirements, " ")
	if len(s) == 2 && s[0] == "=" {
		return s[1]
	}
	// in case of ranged version
	return ""
}
