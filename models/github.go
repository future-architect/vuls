package models

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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
	// https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems
	switch {
	case strings.HasSuffix(m.Lockfile, "Cargo.lock"),
		strings.HasSuffix(m.Lockfile, "Cargo.toml"):
		return ftypes.Cargo // Rust
	case strings.HasSuffix(m.Lockfile, "composer.lock"),
		strings.HasSuffix(m.Lockfile, "composer.json"):
		return ftypes.Composer // PHP
	case strings.HasSuffix(m.Lockfile, ".csproj"),
		strings.HasSuffix(m.Lockfile, ".vbproj"),
		strings.HasSuffix(m.Lockfile, ".nuspec"),
		strings.HasSuffix(m.Lockfile, ".vcxproj"),
		strings.HasSuffix(m.Lockfile, ".fsproj"),
		strings.HasSuffix(m.Lockfile, "packages.config"):
		return ftypes.NuGet // .NET languages (C#, F#, VB), C++
	case strings.HasSuffix(m.Lockfile, "go.sum"),
		strings.HasSuffix(m.Lockfile, "go.mod"):
		return ftypes.GoModule // Go
	case strings.HasSuffix(m.Lockfile, "pom.xml"):
		return ftypes.Pom // Java, Scala
	case strings.HasSuffix(m.Lockfile, "package-lock.json"),
		strings.HasSuffix(m.Lockfile, "package.json"):
		return ftypes.Npm // JavaScript
	case strings.HasSuffix(m.Lockfile, "yarn.lock"):
		return ftypes.Yarn // JavaScript
	case strings.HasSuffix(m.Lockfile, "requirements.txt"),
		strings.HasSuffix(m.Lockfile, "requirements-dev.txt"),
		strings.HasSuffix(m.Lockfile, "setup.py"):
		return ftypes.Pip // Python
	case strings.HasSuffix(m.Lockfile, "Pipfile.lock"),
		strings.HasSuffix(m.Lockfile, "Pipfile"):
		return ftypes.Pipenv // Python
	case strings.HasSuffix(m.Lockfile, "poetry.lock"),
		strings.HasSuffix(m.Lockfile, "pyproject.toml"):
		return ftypes.Poetry // Python
	case strings.HasSuffix(m.Lockfile, "Gemfile.lock"),
		strings.HasSuffix(m.Lockfile, "Gemfile"):
		return ftypes.Bundler // Ruby
	case strings.HasSuffix(m.Lockfile, ".gemspec"):
		return ftypes.GemSpec // Ruby
	case strings.HasSuffix(m.Lockfile, "pubspec.lock"),
		strings.HasSuffix(m.Lockfile, "pubspec.yaml"):
		return "pub" // Dart
	case strings.HasSuffix(m.Lockfile, ".yml"),
		strings.HasSuffix(m.Lockfile, ".yaml"):
		return "actions" // GitHub Actions workflows
	default:
		return "unknown"
	}
}

// equal to DependencyGraphDependency
type Dependency struct {
	PackageName    string `json:"packageName"`
	PackageManager string `json:"packageManager"`
	Repository     string `json:"repository"`
	Requirements   string `json:"requirements"`
}

func (d Dependency) Version() string {
	s := strings.Split(d.Requirements, " ")
	if len(s) == 2 && s[0] == "=" {
		return s[1]
	}
	// TODO: return d.Requirements?
	return ""
}
