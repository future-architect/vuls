package models

import (
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// DependencyGraphManifests has a map of DependencyGraphManifest
// key: Filename
type DependencyGraphManifests map[string]DependencyGraphManifest

type DependencyGraphManifest struct {
	Filename     string       `json:"filename"`
	Repository   string       `json:"repository"`
	Dependencies []Dependency `json:"dependencies"`
}

// Ecosystem returns a name of ecosystem(or package manager) of manifest(lock) file in trivy way
// https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems
func (m DependencyGraphManifest) Ecosystem() string {
	switch {
	case strings.HasSuffix(m.Filename, "Cargo.lock"),
		strings.HasSuffix(m.Filename, "Cargo.toml"):
		return ftypes.Cargo // Rust
	case strings.HasSuffix(m.Filename, "composer.lock"),
		strings.HasSuffix(m.Filename, "composer.json"):
		return ftypes.Composer // PHP
	case strings.HasSuffix(m.Filename, ".csproj"),
		strings.HasSuffix(m.Filename, ".vbproj"),
		strings.HasSuffix(m.Filename, ".nuspec"),
		strings.HasSuffix(m.Filename, ".vcxproj"),
		strings.HasSuffix(m.Filename, ".fsproj"),
		strings.HasSuffix(m.Filename, "packages.config"):
		return ftypes.NuGet // .NET languages (C#, F#, VB), C++
	case strings.HasSuffix(m.Filename, "go.sum"),
		strings.HasSuffix(m.Filename, "go.mod"):
		return ftypes.GoModule // Go
	case strings.HasSuffix(m.Filename, "pom.xml"):
		return ftypes.Pom // Java, Scala
	case strings.HasSuffix(m.Filename, "package-lock.json"),
		strings.HasSuffix(m.Filename, "package.json"):
		return ftypes.Npm // JavaScript
	case strings.HasSuffix(m.Filename, "yarn.lock"):
		return ftypes.Yarn // JavaScript
	case strings.HasSuffix(m.Filename, "requirements.txt"),
		strings.HasSuffix(m.Filename, "requirements-dev.txt"),
		strings.HasSuffix(m.Filename, "setup.py"):
		return ftypes.Pip // Python
	case strings.HasSuffix(m.Filename, "Pipfile.lock"),
		strings.HasSuffix(m.Filename, "Pipfile"):
		return ftypes.Pipenv // Python
	case strings.HasSuffix(m.Filename, "poetry.lock"),
		strings.HasSuffix(m.Filename, "pyproject.toml"):
		return ftypes.Poetry // Python
	case strings.HasSuffix(m.Filename, "Gemfile.lock"),
		strings.HasSuffix(m.Filename, "Gemfile"):
		return ftypes.Bundler // Ruby
	case strings.HasSuffix(m.Filename, ".gemspec"):
		return ftypes.GemSpec // Ruby
	case strings.HasSuffix(m.Filename, "pubspec.lock"),
		strings.HasSuffix(m.Filename, "pubspec.yaml"):
		return "pub" // Dart
	case strings.HasSuffix(m.Filename, ".yml"),
		strings.HasSuffix(m.Filename, ".yaml"):
		return "actions" // GitHub Actions workflows
	default:
		return "unknown"
	}
}

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
	// in case of ranged version
	return ""
}
