package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

func TestParseIfconfig(t *testing.T) {
	var tests = []struct {
		in        string
		expected4 []string
		expected6 []string
	}{
		{
			in: `em0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
			options=9b<RXCSUM,TXCSUM,VLAN_MTU,VLAN_HWTAGGING,VLAN_HWCSUM>
			ether 08:00:27:81:82:fa
			hwaddr 08:00:27:81:82:fa
			inet 10.0.2.15 netmask 0xffffff00 broadcast 10.0.2.255
			inet6 2001:db8::68 netmask 0xffffff00 broadcast 10.0.2.255
			nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>
			media: Ethernet autoselect (1000baseT <full-duplex>)
			status: active
	lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
			options=600003<RXCSUM,TXCSUM,RXCSUM_IPV6,TXCSUM_IPV6>
			inet6 ::1 prefixlen 128
			inet6 fe80::1%lo0 prefixlen 64 scopeid 0x2
			inet 127.0.0.1 netmask 0xff000000
			nd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>`,
			expected4: []string{"10.0.2.15"},
			expected6: []string{"2001:db8::68"},
		},
	}

	d := newBsd(config.ServerInfo{})
	for _, tt := range tests {
		actual4, actual6 := d.parseIfconfig(tt.in)
		if !reflect.DeepEqual(tt.expected4, actual4) {
			t.Errorf("expected %s, actual %s", tt.expected4, actual4)
		}
		if !reflect.DeepEqual(tt.expected6, actual6) {
			t.Errorf("expected %s, actual %s", tt.expected6, actual6)
		}
	}
}

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
