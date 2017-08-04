package scan

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
			`
block1

block2
block2
block2

block3
block3`,
			[]string{
				`block1`,
				"block2\nblock2\nblock2",
				"block3\nblock3",
			},
		},
	}

	d := newBsd(config.ServerInfo{})
	for _, tt := range tests {
		actual := d.splitIntoBlocks(tt.in)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("expected %s, actual %s", e, a)
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
