package vulnsrc

// https://github.com/MaineK00n/vuls-data-update/blob/main/pkg/build/types.go

import "time"

type Vulnerability struct {
	ID          string        `json:"id,omitempty"`
	Advisory    *Advisories   `json:"advisory,omitempty"`
	Title       *Titles       `json:"title,omitempty"`
	Description *Descriptions `json:"description,omitempty"`
	CVSS        *CVSSes       `json:"cvss,omitempty"`
	EPSS        *EPSS         `json:"epss,omitempty"`
	CWE         *CWEs         `json:"cwe,omitempty"`
	Metasploit  []Metasploit  `json:"metasploit,omitempty"`
	Exploit     *Exploit      `json:"exploit,omitempty"`
	KEV         *KEV          `json:"kev,omitempty"`
	Mitigation  *Mitigation   `json:"mitigation,omitempty"`
	Published   *Publisheds   `json:"published,omitempty"`
	Modified    *Modifieds    `json:"modified,omitempty"`
	References  *References   `json:"references,omitempty"`
}

type Advisories struct {
	MITRE                 *Advisory             `json:"mitre,omitempty"`
	NVD                   *Advisory             `json:"nvd,omitempty"`
	JVN                   []Advisory            `json:"jvn,omitempty"`
	Alma                  map[string][]Advisory `json:"alma,omitempty"`
	Alpine                map[string]Advisory   `json:"alpine,omitempty"`
	Amazon                map[string][]Advisory `json:"amazon,omitempty"`
	Arch                  []Advisory            `json:"arch,omitempty"`
	DebianOVAL            map[string][]Advisory `json:"debian_oval,omitempty"`
	DebianSecurityTracker map[string]Advisory   `json:"debian_security_tracker,omitempty"`
	FreeBSD               []Advisory            `json:"freebsd,omitempty"`
	Oracle                map[string][]Advisory `json:"oracle,omitempty"`
	RedHatOVAL            map[string][]Advisory `json:"redhat_oval,omitempty"`
	SUSEOVAL              map[string][]Advisory `json:"suse_oval,omitempty"`
	SUSECVRF              *Advisory             `json:"suse_cvrf,omitempty"`
	UbuntuOVAL            map[string][]Advisory `json:"ubuntu_oval,omitempty"`
	UbuntuSecurityTracker *Advisory             `json:"ubuntu_security_tracker,omitempty"`
}
type Advisory struct {
	ID  string `json:"id,omitempty"`
	URL string `json:"url,omitempty"`
}

type Titles struct {
	MITRE                 string                       `json:"mitre,omitempty"`
	NVD                   string                       `json:"nvd,omitempty"`
	JVN                   map[string]string            `json:"jvn,omitempty"`
	Alma                  map[string]map[string]string `json:"alma,omitempty"`
	Alpine                map[string]string            `json:"alpine,omitempty"`
	Amazon                map[string]map[string]string `json:"amazon,omitempty"`
	Arch                  map[string]string            `json:"arch,omitempty"`
	DebianOVAL            map[string]map[string]string `json:"debian_oval,omitempty"`
	DebianSecurityTracker map[string]string            `json:"debian_security_tracker,omitempty"`
	FreeBSD               map[string]string            `json:"freebsd,omitempty"`
	Oracle                map[string]map[string]string `json:"oracle,omitempty"`
	RedHatOVAL            map[string]map[string]string `json:"redhat_oval,omitempty"`
	SUSEOVAL              map[string]map[string]string `json:"suse_oval,omitempty"`
	SUSECVRF              string                       `json:"suse_cvrf,omitempty"`
	UbuntuOVAL            map[string]map[string]string `json:"ubuntu_oval,omitempty"`
	UbuntuSecurityTracker string                       `json:"ubuntu_security_tracker,omitempty"`
}

type Descriptions struct {
	MITRE                 string                       `json:"mitre,omitempty"`
	NVD                   string                       `json:"nvd,omitempty"`
	JVN                   map[string]string            `json:"jvn,omitempty"`
	Alma                  map[string]map[string]string `json:"alma,omitempty"`
	Amazon                map[string]map[string]string `json:"amazon,omitempty"`
	DebianOVAL            map[string]map[string]string `json:"debian_oval,omitempty"`
	DebianSecurityTracker map[string]string            `json:"debian_security_tracker,omitempty"`
	FreeBSD               map[string]string            `json:"freebsd,omitempty"`
	Oracle                map[string]map[string]string `json:"oracle,omitempty"`
	RedHatOVAL            map[string]map[string]string `json:"redhat_oval,omitempty"`
	SUSEOVAL              map[string]map[string]string `json:"suse_oval,omitempty"`
	SUSECVRF              string                       `json:"suse_cvrf,omitempty"`
	UbuntuOVAL            map[string]map[string]string `json:"ubuntu_oval,omitempty"`
	UbuntuSecurityTracker string                       `json:"ubuntu_security_tracker,omitempty"`
}

type CVSSes struct {
	NVD                   []CVSS                       `json:"nvd,omitempty"`
	JVN                   map[string][]CVSS            `json:"jvn,omitempty"`
	Alma                  map[string]map[string][]CVSS `json:"alma,omitempty"`
	Amazon                map[string]map[string][]CVSS `json:"amazon,omitempty"`
	Arch                  map[string][]CVSS            `json:"arch,omitempty"`
	Oracle                map[string]map[string][]CVSS `json:"oracle,omitempty"`
	RedHatOVAL            map[string]map[string][]CVSS `json:"redhat_oval,omitempty"`
	SUSEOVAL              map[string]map[string][]CVSS `json:"suse_oval,omitempty"`
	SUSECVRF              []CVSS                       `json:"suse_cvrf,omitempty"`
	UbuntuOVAL            map[string]map[string][]CVSS `json:"ubuntu_oval,omitempty"`
	UbuntuSecurityTracker []CVSS                       `json:"ubuntu_security_tracker,omitempty"`
}

type CVSS struct {
	Version  string   `json:"version,omitempty"`
	Source   string   `json:"source,omitempty"`
	Vector   string   `json:"vector,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Severity string   `json:"severity,omitempty"`
}

type EPSS struct {
	EPSS       *float64 `json:"epss,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}

type CWEs struct {
	NVD        []string                       `json:"nvd,omitempty"`
	JVN        map[string][]string            `json:"jvn,omitempty"`
	RedHatOVAL map[string]map[string][]string `json:"redhat_oval,omitempty"`
}

type Metasploit struct {
	Name        string   `json:"name,omitempty"`
	Title       string   `json:"title,omitempty"`
	Description string   `json:"description,omitempty"`
	URLs        []string `json:"urls,omitempty"`
}

type Exploit struct {
	NVD       []string    `json:"nvd,omitempty"`
	ExploitDB []ExploitDB `json:"exploit_db,omitempty"`
	GitHub    []GitHub    `json:"github,omitempty"`
	InTheWild []InTheWild `json:"inthewild,omitempty"`
	Trickest  *Trickest   `json:"trickest,omitempty"`
}

type ExploitDB struct {
	ID          string `json:"name,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url,omitempty"`
	FileURL     string `json:"file_url,omitempty"`
}

type GitHub struct {
	Name    string `json:"name,omitempty"`
	Stars   int    `json:"stars"`
	Forks   int    `json:"forks"`
	Watches int    `json:"watches"`
	URL     string `json:"url,omitempty"`
}

type InTheWild struct {
	Source string `json:"source,omitempty"`
	URL    string `json:"url,omitempty"`
}

type Trickest struct {
	Description string       `json:"description,omitempty"`
	PoC         *TrickestPoc `json:"poc,omitempty"`
}

type TrickestPoc struct {
	Reference []string `json:"reference,omitempty"`
	GitHub    []string `json:"github,omitempty"`
}

type KEV struct {
	Title          string     `json:"title,omitempty"`
	Description    string     `json:"description,omitempty"`
	RequiredAction string     `json:"required_action,omitempty"`
	DueDate        *time.Time `json:"due_date,omitempty"`
}

type Mitigation struct {
	NVD                   []string `json:"nvd,omitempty"`
	UbuntuSecurityTracker string   `json:"ubuntu_security_tracker,omitempty"`
}

type Publisheds struct {
	MITRE                 *time.Time                       `json:"mitre,omitempty"`
	NVD                   *time.Time                       `json:"nvd,omitempty"`
	JVN                   map[string]*time.Time            `json:"jvn,omitempty"`
	Alma                  map[string]map[string]*time.Time `json:"alma,omitempty"`
	Amazon                map[string]map[string]*time.Time `json:"amazon,omitempty"`
	FreeBSD               map[string]*time.Time            `json:"freebsd,omitempty"`
	Oracle                map[string]map[string]*time.Time `json:"oracle,omitempty"`
	RedHatOVAL            map[string]map[string]*time.Time `json:"redhat_oval,omitempty"`
	SUSEOVAL              map[string]map[string]*time.Time `json:"suse_oval,omitempty"`
	SUSECVRF              *time.Time                       `json:"suse_cvrf,omitempty"`
	UbuntuOVAL            map[string]map[string]*time.Time `json:"ubuntu_oval,omitempty"`
	UbuntuSecurityTracker *time.Time                       `json:"ubuntu_security_tracker,omitempty"`
}

type Modifieds struct {
	MITRE      *time.Time                       `json:"mitre,omitempty"`
	NVD        *time.Time                       `json:"nvd,omitempty"`
	JVN        map[string]*time.Time            `json:"jvn,omitempty"`
	Alma       map[string]map[string]*time.Time `json:"alma,omitempty"`
	Amazon     map[string]map[string]*time.Time `json:"amazon,omitempty"`
	FreeBSD    map[string]*time.Time            `json:"freebsd,omitempty"`
	RedHatOVAL map[string]map[string]*time.Time `json:"redhat_oval,omitempty"`
	SUSEOVAL   map[string]map[string]*time.Time `json:"suse_oval,omitempty"`
	SUSECVRF   *time.Time                       `json:"suse_cvrf,omitempty"`
}

type References struct {
	MITRE                 []Reference                       `json:"mitre,omitempty"`
	NVD                   []Reference                       `json:"nvd,omitempty"`
	JVN                   map[string][]Reference            `json:"jvn,omitempty"`
	Alma                  map[string]map[string][]Reference `json:"alma,omitempty"`
	Amazon                map[string]map[string][]Reference `json:"amazon,omitempty"`
	Arch                  map[string][]Reference            `json:"arch,omitempty"`
	DebianOVAL            map[string]map[string][]Reference `json:"debian_oval,omitempty"`
	DebianSecurityTracker map[string][]Reference            `json:"debian_security_tracker,omitempty"`
	FreeBSD               map[string][]Reference            `json:"freebsd,omitempty"`
	Oracle                map[string]map[string][]Reference `json:"oracle,omitempty"`
	RedHatOVAL            map[string]map[string][]Reference `json:"redhat_oval,omitempty"`
	SUSEOVAL              map[string]map[string][]Reference `json:"suse_oval,omitempty"`
	SUSECVRF              []Reference                       `json:"suse_cvrf,omitempty"`
	UbuntuOVAL            map[string]map[string][]Reference `json:"ubuntu_oval,omitempty"`
	UbuntuSecurityTracker []Reference                       `json:"ubuntu_security_tracker,omitempty"`
}

type Reference struct {
	Source string   `json:"source,omitempty"`
	Name   string   `json:"name,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url,omitempty"`
}

type DetectCPE struct {
	ID             string                        `json:"id,omitempty"`
	Configurations map[string][]CPEConfiguration `json:"configurations,omitempty"`
}

type CPEConfiguration struct {
	Vulnerable []CPE `json:"vulnerable,omitempty"`
	RunningOn  []CPE `json:"running_on,omitempty"`
}

type CPE struct {
	CPEVersion string    `json:"cpe_version,omitempty"`
	CPE        string    `json:"cpe,omitempty"`
	Version    []Version `json:"version,omitempty"`
}

type DetectPackage struct {
	ID       string               `json:"id,omitempty"`
	Packages map[string][]Package `json:"packages,omitempty"`
}

type Package struct {
	Name            string      `json:"name,omitempty"`
	Status          string      `json:"status,omitempty"`
	Version         [][]Version `json:"version,omitempty"`
	ModularityLabel string      `json:"modularity_label,omitempty"`
	Arch            []string    `json:"arch,omitempty"`
	Repository      string      `json:"repository,omitempty"`
	CPE             []string    `json:"cpe,omitempty"`
}

type Version struct {
	Operator string `json:"operator,omitempty"`
	Version  string `json:"version,omitempty"`
}

type RepositoryToCPE map[string][]string

type Supercedence struct {
	KBID         string `json:"KBID,omitempty"`
	Supersededby struct {
		KBIDs []string `json:"KBIDs,omitempty"`
	} `json:"Supersededby,omitempty"`
}
