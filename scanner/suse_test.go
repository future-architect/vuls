package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

func TestScanUpdatablePackages(t *testing.T) {
	r := newSUSE(config.ServerInfo{})
	r.Distro = config.Distro{Family: "sles"}
	stdout := `S | Repository                                  | Name                          | Current Version             | Available Version           | Arch
--+---------------------------------------------+-------------------------------+-----------------------------+-----------------------------+-------
v | SLES12-SP2-Updates                          | SUSEConnect                   | 0.3.0-19.8.1                | 0.3.1-19.11.2               | x86_64
v | SLES12-SP2-Updates                          | SuSEfirewall2                 | 3.6.312-2.3.1               | 3.6.312-2.10.1              | noarch
v | Clone of SLES11-SP3-Updates for x86_64 | ConsoleKit | 0.2.10-64.65.1 | 0.2.10-64.69.1 | x86_64`

	var tests = []struct {
		in  string
		out models.Packages
	}{
		{
			stdout,
			models.NewPackages(
				models.Package{
					Name:       "SUSEConnect",
					NewVersion: "0.3.1",
					NewRelease: "19.11.2",
					Arch:       "x86_64",
				},
				models.Package{
					Name:       "SuSEfirewall2",
					NewVersion: "3.6.312",
					NewRelease: "2.10.1",
					Arch:       "noarch",
				},
				models.Package{
					Name:       "ConsoleKit",
					NewVersion: "0.2.10",
					NewRelease: "64.69.1",
					Arch:       "x86_64",
				},
			),
		},
	}

	for _, tt := range tests {
		packages, err := r.parseZypperLULines(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %+v\ntt.in: %v", err, tt.in)
			return
		}
		for name, ePack := range tt.out {
			if !reflect.DeepEqual(ePack, packages[name]) {
				e := pp.Sprintf("%v", ePack)
				a := pp.Sprintf("%v", packages[name])
				t.Errorf("expected %s, actual %s", e, a)
			}
		}
	}
}

func TestScanUpdatablePackage(t *testing.T) {
	r := newSUSE(config.ServerInfo{})
	r.Distro = config.Distro{Family: "sles"}
	stdout := `v | SLES12-SP2-Updates                          | SUSEConnect                   | 0.3.0-19.8.1                | 0.3.1-19.11.2               | x86_64`

	var tests = []struct {
		in  string
		out models.Package
	}{
		{
			stdout,
			models.Package{
				Name:       "SUSEConnect",
				NewVersion: "0.3.1",
				NewRelease: "19.11.2",
				Arch:       "x86_64",
			},
		},
	}

	for _, tt := range tests {
		pack, err := r.parseZypperLUOneLine(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %+v\ntt.in: %v", err, tt.in)
			return
		}
		if !reflect.DeepEqual(*pack, tt.out) {
			e := pp.Sprintf("%v", tt.out)
			a := pp.Sprintf("%v", pack)
			t.Errorf("expected %s, actual %s", e, a)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	var tests = []struct {
		in   string
		name string
		ver  string
	}{
		{
			in: `CPE_NAME="cpe:/o:opensuse:opensuse:13.2"
VERSION_ID="13.2"`,
			name: constant.OpenSUSE,
			ver:  "13.2",
		},
		{
			in: `CPE_NAME="cpe:/o:opensuse:tumbleweed:20220124"
VERSION_ID="20220124"`,
			name: constant.OpenSUSE,
			ver:  "tumbleweed",
		},
		{
			in: `CPE_NAME="cpe:/o:opensuse:leap:42.3"
VERSION_ID="42.3.4"`,
			name: constant.OpenSUSELeap,
			ver:  "42.3.4",
		},
		{
			in: `CPE_NAME="cpe:/o:suse:sles:12:sp1"
VERSION_ID="12.1"`,
			name: constant.SUSEEnterpriseServer,
			ver:  "12.1",
		},
		{
			in: `CPE_NAME="cpe:/o:suse:sles_sap:12:sp1"
VERSION_ID="12.1.0.1"`,
			name: constant.SUSEEnterpriseServer,
			ver:  "12.1.0.1",
		},
		{
			in: `CPE_NAME="cpe:/o:suse:sled:15"
VERSION_ID="15"`,
			name: constant.SUSEEnterpriseDesktop,
			ver:  "15",
		},
	}

	r := newSUSE(config.ServerInfo{})
	for i, tt := range tests {
		name, ver := r.parseOSRelease(tt.in)
		if tt.name != name {
			t.Errorf("[%d] expected %s, actual %s", i, tt.name, name)
		}
		if tt.ver != ver {
			t.Errorf("[%d] expected %s, actual %s", i, tt.ver, ver)
		}
	}
}
