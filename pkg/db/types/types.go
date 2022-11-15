package types

import "time"

type Vulnerability struct {
	ID          string       `json:"id,omitempty"`
	Advisory    []string     `json:"advisory,omitempty"`
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	CVSS        []CVSS       `json:"cvss,omitempty"`
	EPSS        *EPSS        `json:"epss,omitempty"`
	CWE         []CWE        `json:"cwe,omitempty"`
	Metasploit  []Metasploit `json:"metasploit,omitempty"`
	Exploit     []Exploit    `json:"exploit,omitempty"`
	KEV         bool         `json:"kev,omitempty"`
	Published   *time.Time   `json:"published,omitempty"`
	Modified    *time.Time   `json:"modified,omitempty"`
	Reference   []string     `json:"reference,omitempty"`
}

type CVSS struct {
	Source   string   `json:"source,omitempty"`
	Version  string   `json:"version,omitempty"`
	Vector   string   `json:"vector,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type EPSS struct {
	EPSS       *float64 `json:"epss,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}

type CWE struct {
	Source []string `json:"source,omitempty"`
	ID     string   `json:"id,omitempty"`
}

type Metasploit struct {
	Title string `json:"title,omitempty"`
	URL   string `json:"url,omitempty"`
}

type Exploit struct {
	Source []string `json:"source,omitempty"`
	URL    string   `json:"url,omitempty"`
}

type CPEConfigurations struct {
	ID            string                        `json:"-,omitempty"`
	Configuration map[string][]CPEConfiguration `json:"configuration,omitempty"`
}

type CPEConfiguration struct {
	Vulnerable CPE   `json:"vulnerable,omitempty"`
	RunningOn  []CPE `json:"running_on,omitempty"`
}

type CPE struct {
	CPEVersion string    `json:"cpe_version,omitempty"`
	CPE        string    `json:"cpe,omitempty"`
	Version    []Version `json:"version,omitempty"`
}

type Packages struct {
	ID      string             `json:"-,omitempty"`
	Package map[string]Package `json:"package,omitempty"`
}

type Package struct {
	Status     string      `json:"status,omitempty"`
	Version    [][]Version `json:"version,omitempty"`
	Arch       []string    `json:"arch,omitempty"`
	Repository string      `json:"repository,omitempty"`
	CPE        []string    `json:"cpe,omitempty"`
}

type Version struct {
	Operator string `json:"operator,omitempty"`
	Version  string `json:"version,omitempty"`
}

type RepositoryToCPE map[string][]string

type Supercedence map[string][]string
