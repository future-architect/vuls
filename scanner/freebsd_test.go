package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

func TestParsePkgVersion(t *testing.T) {
	var tests = []struct {
		in       string
		expected models.Packages
	}{
		{
			`Updating FreeBSD repository catalogue...
FreeBSD repository is up-to-date.
All repositories are up-to-date.
bash-4.2.45                        <   needs updating (remote has 4.3.42_1)
gettext-0.18.3.1                   <   needs updating (remote has 0.19.7)
tcl84-8.4.20_2,1                   =   up-to-date with remote
ntp-4.2.8p8_1                      >   succeeds port (port has 4.2.8p6)
teTeX-base-3.0_25                  ?   orphaned: print/teTeX-base`,

			models.Packages{
				"bash": {
					Name:       "bash",
					Version:    "4.2.45",
					NewVersion: "4.3.42_1",
				},
				"gettext": {
					Name:       "gettext",
					Version:    "0.18.3.1",
					NewVersion: "0.19.7",
				},
				"tcl84": {
					Name:    "tcl84",
					Version: "8.4.20_2,1",
				},
				"teTeX-base": {
					Name:    "teTeX-base",
					Version: "3.0_25",
				},
				"ntp": {
					Name:    "ntp",
					Version: "4.2.8p8_1",
				},
			},
		},
	}

	d := newBsd(config.ServerInfo{})
	for _, tt := range tests {
		actual := d.parsePkgVersion(tt.in)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("expected %s, actual %s", e, a)
		}
	}
}

func TestSplitIntoBlocks(t *testing.T) {
	var tests = []struct {
		in       string
		expected []string
	}{
		{
			`vulnxml file up-to-date
bind95-9.6.3.2.ESV.R10_2 is vulnerable:
bind -- denial of service vulnerability
CVE: CVE-2014-8680
CVE: CVE-2014-8500
WWW: https://vuxml.FreeBSD.org/freebsd/ab3e98d9-8175-11e4-907d-d050992ecde8.html

go-1.17.1,1 is vulnerable:
  go -- multiple vulnerabilities
  CVE: CVE-2021-41772
  CVE: CVE-2021-41771
  WWW: https://vuxml.FreeBSD.org/freebsd/930def19-3e05-11ec-9ba8-002324b2fba8.html

  go -- misc/wasm, cmd/link: do not let command line arguments overwrite global data
  CVE: CVE-2021-38297
  WWW: https://vuxml.FreeBSD.org/freebsd/4fce9635-28c0-11ec-9ba8-002324b2fba8.html

  Packages that depend on go: 

2 problem(s) in 1 installed package(s) found.`,
			[]string{
				`bind95-9.6.3.2.ESV.R10_2 is vulnerable:
bind -- denial of service vulnerability
CVE: CVE-2014-8680
CVE: CVE-2014-8500
WWW: https://vuxml.FreeBSD.org/freebsd/ab3e98d9-8175-11e4-907d-d050992ecde8.html
`,
				`go-1.17.1,1 is vulnerable:
go -- multiple vulnerabilities
CVE: CVE-2021-41772
CVE: CVE-2021-41771
WWW: https://vuxml.FreeBSD.org/freebsd/930def19-3e05-11ec-9ba8-002324b2fba8.html

go -- misc/wasm, cmd/link: do not let command line arguments overwrite global data
CVE: CVE-2021-38297
WWW: https://vuxml.FreeBSD.org/freebsd/4fce9635-28c0-11ec-9ba8-002324b2fba8.html

Packages that depend on go:

2 problem(s) in 1 installed package(s) found.`},
		},
	}

	d := newBsd(config.ServerInfo{})
	for _, tt := range tests {
		actual := d.splitIntoBlocks(tt.in)
		if !reflect.DeepEqual(tt.expected, actual) {
			pp.ColoringEnabled = false
			t.Errorf("expected %s\n, actual %s",
				pp.Sprintf("%s", tt.expected),
				pp.Sprintf("%s", actual))
		}
	}

}

func TestParseBlock(t *testing.T) {
	var tests = []struct {
		in     string
		name   string
		cveIDs []string
		vulnID string
	}{
		{

			in: `vulnxml file up-to-date
bind96-9.6.3.2.ESV.R10_2 is vulnerable:
bind -- denial of service vulnerability
CVE: CVE-2014-0591
WWW: https://vuxml.FreeBSD.org/freebsd/cb252f01-7c43-11e3-b0a6-005056a37f68.html`,
			name:   "bind96",
			cveIDs: []string{"CVE-2014-0591"},
			vulnID: "cb252f01-7c43-11e3-b0a6-005056a37f68",
		},
		{
			in: `bind96-9.6.3.2.ESV.R10_2 is vulnerable:
bind -- denial of service vulnerability
CVE: CVE-2014-8680
CVE: CVE-2014-8500
WWW: https://vuxml.FreeBSD.org/freebsd/ab3e98d9-8175-11e4-907d-d050992ecde8.html`,
			name:   "bind96",
			cveIDs: []string{"CVE-2014-8680", "CVE-2014-8500"},
			vulnID: "ab3e98d9-8175-11e4-907d-d050992ecde8",
		},
		{
			in: `hoge-hoge-9.6.3.2.ESV.R10_2 is vulnerable:
bind -- denial of service vulnerability
CVE: CVE-2014-8680
CVE: CVE-2014-8500
WWW: https://vuxml.FreeBSD.org/freebsd/ab3e98d9-8175-11e4-907d-d050992ecde8.html`,
			name:   "hoge-hoge",
			cveIDs: []string{"CVE-2014-8680", "CVE-2014-8500"},
			vulnID: "ab3e98d9-8175-11e4-907d-d050992ecde8",
		},
		{
			in:     `1 problem(s) in the installed packages found.`,
			cveIDs: []string{},
			vulnID: "",
		},
		{
			in: `vulnxml file up-to-date
libxml2-2.9.10 is vulnerable:
libxml -- multiple vulnerabilities
WWW: https://vuxml.FreeBSD.org/freebsd/f5abafc0-fcf6-11ea-8758-e0d55e2a8bf9.html`,
			name:   "libxml2",
			cveIDs: []string{},
			vulnID: "f5abafc0-fcf6-11ea-8758-e0d55e2a8bf9",
		},
		{
			in: `go-1.17.1,1 is vulnerable:
go -- multiple vulnerabilities
CVE: CVE-2021-41772
CVE: CVE-2021-41771
WWW: https://vuxml.FreeBSD.org/freebsd/930def19-3e05-11ec-9ba8-002324b2fba8.html`,
			name:   "go",
			cveIDs: []string{"CVE-2021-41772", "CVE-2021-41771"},
			vulnID: "930def19-3e05-11ec-9ba8-002324b2fba8",
		},
		{
			in: `go-1.17.1,1 is vulnerable:
go -- multiple vulnerabilities
CVE: CVE-2021-41772
CVE: CVE-2021-41771
WWW: https://vuxml.FreeBSD.org/freebsd/930def19-3e05-11ec-9ba8-002324b2fba8.html

go -- misc/wasm, cmd/link: do not let command line arguments overwrite global data
CVE: CVE-2021-38297
WWW: https://vuxml.FreeBSD.org/freebsd/4fce9635-28c0-11ec-9ba8-002324b2fba8.html`,
			name:   "go",
			cveIDs: []string{"CVE-2021-41772", "CVE-2021-41771", "CVE-2021-38297"},
			vulnID: "4fce9635-28c0-11ec-9ba8-002324b2fba8",
		},
	}

	d := newBsd(config.ServerInfo{})
	for _, tt := range tests {
		aName, aCveIDs, aVulnID := d.parseBlock(tt.in)
		if tt.name != aName {
			t.Errorf("expected vulnID: %s, actual %s", tt.vulnID, aVulnID)
		}
		for i := range tt.cveIDs {
			if tt.cveIDs[i] != aCveIDs[i] {
				t.Errorf("expected cveID: %s, actual %s", tt.cveIDs[i], aCveIDs[i])
			}
		}
		if tt.vulnID != aVulnID {
			t.Errorf("expected vulnID: %s, actual %s", tt.vulnID, aVulnID)
		}
	}
}

func TestParsePkgInfo(t *testing.T) {
	var tests = []struct {
		in       string
		expected models.Packages
	}{
		{
			`bash-4.2.45                        Universal Command Line Interface for Amazon Web Services
gettext-0.18.3.1                   Startup scripts for FreeBSD/EC2 environment
tcl84-8.4.20_2,1                   Update the system using freebsd-update when it first boots
ntp-4.2.8p8_1                      GNU gettext runtime libraries and programs
teTeX-base-3.0_25                  Foreign Function Interface`,
			models.Packages{
				"bash": {
					Name:    "bash",
					Version: "4.2.45",
				},
				"gettext": {
					Name:    "gettext",
					Version: "0.18.3.1",
				},
				"tcl84": {
					Name:    "tcl84",
					Version: "8.4.20_2,1",
				},
				"teTeX-base": {
					Name:    "teTeX-base",
					Version: "3.0_25",
				},
				"ntp": {
					Name:    "ntp",
					Version: "4.2.8p8_1",
				},
			},
		},
	}

	d := newBsd(config.ServerInfo{})
	for _, tt := range tests {
		actual := d.parsePkgInfo(tt.in)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("expected %s, actual %s", e, a)
		}
	}
}
