package models

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
	// TODO: convert from lock filename?
	// https://docs.github.com/en/code-security/supply-chain-security/understanding-your-software-supply-chain/about-the-dependency-graph#supported-package-ecosystems
	//switch case strings.Contains(m.Lockfile, "go.sum"): return "GO"
	return "UNKNOWN"
}

// equal to DependencyGraphDependency
type Dependency struct {
	PackageName    string `json:"packageName"`
	PackageManager string `json:"packageManager"`
	Repository     string `json:"repository"`
	Requirements   string `json:"requirements"`
}

func (d Dependency) Version() string {
	// TODO: convert requirements to version
	return d.Requirements
}
