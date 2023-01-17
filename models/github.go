package models

import (
	"regexp"
	"strings"
)

// key: Lockfile
type DependencyGraphManifests map[string]DependencyGraphManifest

type DependencyGraphManifest struct {
	Lockfile     string       `json:"lockfile"`
	Repository   string       `json:"repository"`
	Dependencies []Dependency `json:"dependencies"`
}

func (m DependencyGraphManifest) Ecosystem() string {
	if len(m.Dependencies) > 0 {
		return m.Dependencies[0].PackageManager
	}

	// https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems
	switch {
	case strings.HasSuffix(m.Lockfile, "Cargo.lock"),
		strings.HasSuffix(m.Lockfile, "Cargo.toml"):
		return "RUST" // Rust
	case strings.HasSuffix(m.Lockfile, "composer.lock"),
		strings.HasSuffix(m.Lockfile, "composer.json"):
		return "COMPOSER" // PHP
	case strings.HasSuffix(m.Lockfile, ".csproj"),
		strings.HasSuffix(m.Lockfile, ".vbproj"),
		strings.HasSuffix(m.Lockfile, ".nuspec"),
		strings.HasSuffix(m.Lockfile, ".vcxproj"),
		strings.HasSuffix(m.Lockfile, ".fsproj"),
		strings.HasSuffix(m.Lockfile, "packages.config"):
		return "NUGET" // .NET languages (C#, F#, VB), C++
	case strings.HasSuffix(m.Lockfile, "go.sum"),
		strings.HasSuffix(m.Lockfile, "go.mod"):
		return "GO" // Go
	case strings.HasSuffix(m.Lockfile, "pom.xml"):
		return "MAVEN" // Java, Scala
	case strings.HasSuffix(m.Lockfile, "package-lock.json"),
		strings.HasSuffix(m.Lockfile, "yarn.lock"),
		strings.HasSuffix(m.Lockfile, "package.json"):
		return "NPM" // JavaScript
	case strings.HasSuffix(m.Lockfile, "requirements.txt"),
		strings.HasSuffix(m.Lockfile, "requirements-dev.txt"),
		strings.HasSuffix(m.Lockfile, "Pipfile.lock"),
		strings.HasSuffix(m.Lockfile, "Pipfile"),
		strings.HasSuffix(m.Lockfile, "setup.py"),
		strings.HasSuffix(m.Lockfile, "poetry.lock"),
		strings.HasSuffix(m.Lockfile, "pyproject.toml"):
		return "PIP" // Python
	case strings.HasSuffix(m.Lockfile, "Gemfile.lock"),
		strings.HasSuffix(m.Lockfile, "Gemfile"),
		strings.HasSuffix(m.Lockfile, ".gemspec"):
		return "RUBYGEMS" // Ruby
	case strings.HasSuffix(m.Lockfile, "pubspec.lock"),
		strings.HasSuffix(m.Lockfile, "pubspec.yaml"):
		return "PUB" // Dart
	case strings.HasSuffix(m.Lockfile, ".yml"),
		strings.HasSuffix(m.Lockfile, ".yaml"):
		return "ACTIONS" // GitHub Actions workflows
	default:
		return "UNKNOWN"
	}
}

// equal to DependencyGraphDependency
type Dependency struct {
	PackageName    string `json:"packageName"`
	PackageManager string `json:"packageManager"`
	Repository     string `json:"repository"`
	Requirements   string `json:"requirements"`
}

var reDepReq = regexp.MustCompile(`^= ([a-z\d\-\.\+]+)$`)

func (d Dependency) Version() string {
	if match := reDepReq.FindStringSubmatch(d.Requirements); len(match) == 2 {
		return match[1]
	}
	return ""
}
