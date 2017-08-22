/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package scan

import (
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

//  func unixtimeNoerr(s string) time.Time {
//      t, _ := unixtime(s)
//      return t
//  }

func TestParseScanedPackagesLineRedhat(t *testing.T) {

	r := newRedhat(config.ServerInfo{})

	var packagetests = []struct {
		in   string
		pack models.Package
	}{
		{
			"openssl	0	1.0.1e	30.el6.11 x86_64",
			models.Package{
				Name:    "openssl",
				Version: "1.0.1e",
				Release: "30.el6.11",
			},
		},
		{
			"Percona-Server-shared-56	1	5.6.19	rel67.0.el6 x84_64",
			models.Package{
				Name:    "Percona-Server-shared-56",
				Version: "1:5.6.19",
				Release: "rel67.0.el6",
			},
		},
	}

	for _, tt := range packagetests {
		p, _ := r.parseInstalledPackagesLine(tt.in)
		if p.Name != tt.pack.Name {
			t.Errorf("name: expected %s, actual %s", tt.pack.Name, p.Name)
		}
		if p.Version != tt.pack.Version {
			t.Errorf("version: expected %s, actual %s", tt.pack.Version, p.Version)
		}
		if p.Release != tt.pack.Release {
			t.Errorf("release: expected %s, actual %s", tt.pack.Release, p.Release)
		}
	}

}

func TestChangeSectionState(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		oldState int
		newState int
	}{
		{Outside, Header},
		{Header, Content},
		{Content, Header},
	}

	for _, tt := range tests {
		if n := r.changeSectionState(tt.oldState); n != tt.newState {
			t.Errorf("expected %d, actual %d", tt.newState, n)
		}
	}
}

func TestParseYumUpdateinfoLineToGetCveIDs(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in  string
		out []string
	}{
		{
			"Bugs : 1194651 - CVE-2015-0278 libuv:",
			[]string{"CVE-2015-0278"},
		},
		{
			": 1195457 - nodejs-0.10.35 causes undefined symbolsCVE-2015-0278, CVE-2015-0278, CVE-2015-02770000000 ",
			[]string{
				"CVE-2015-0278",
				"CVE-2015-0278",
				"CVE-2015-02770000000",
			},
		},
	}

	for _, tt := range tests {
		act := r.parseYumUpdateinfoLineToGetCveIDs(tt.in)
		for i, s := range act {
			if s != tt.out[i] {
				t.Errorf("expected %s, actual %s", tt.out[i], s)
			}
		}
	}
}

func TestParseYumUpdateinfoToGetAdvisoryID(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in    string
		out   string
		found bool
	}{
		{
			"Update ID : RHSA-2015:2315",
			"RHSA-2015:2315",
			true,
		},
		{
			"Update ID : ALAS-2015-620",
			"ALAS-2015-620",
			true,
		},
		{
			"Issued : 2015-11-19 00:00:00",
			"",
			false,
		},
	}

	for _, tt := range tests {
		advisoryID, found := r.parseYumUpdateinfoToGetAdvisoryID(tt.in)
		if tt.out != advisoryID {
			t.Errorf("expected %s, actual %s", tt.out, advisoryID)
		}
		if tt.found != found {
			t.Errorf("expected %t, actual %t", tt.found, found)
		}
	}
}

func TestParseYumUpdateinfoLineToGetIssued(t *testing.T) {

	date, _ := time.Parse("2006-01-02", "2015-12-15")

	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in    string
		out   time.Time
		found bool
	}{
		{
			"Issued : 2015-12-15 00:00:00",
			date,
			true,
		},
		{
			"        Issued : 2015-12-15 00:00:00     ",
			date,
			true,
		},
		{
			"Type : security",
			time.Time{},
			false,
		},
	}

	for i, tt := range tests {
		d, found := r.parseYumUpdateinfoLineToGetIssued(tt.in)
		if tt.found != found {
			t.Errorf("[%d] line: %s, expected %t, actual %t", i, tt.in, tt.found, found)
		}
		if tt.out != d {
			t.Errorf("[%d] line: %s, expected %v, actual %v", i, tt.in, tt.out, d)
		}
	}
}

func TestParseYumUpdateinfoLineToGetUpdated(t *testing.T) {

	date, _ := time.Parse("2006-01-02", "2015-12-15")

	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in    string
		out   time.Time
		found bool
	}{
		{
			"Updated : 2015-12-15 00:00:00       Bugs : 1286966 - CVE-2015-8370 grub2: buffer overflow when checking password entered during bootup",
			date,
			true,
		},
		{

			"Updated : 2015-12-15 14:16       CVEs : CVE-2015-7981",
			date,
			true,
		},
		{
			"Type : security",
			time.Time{},
			false,
		},
	}

	for i, tt := range tests {
		d, found := r.parseYumUpdateinfoLineToGetUpdated(tt.in)
		if tt.found != found {
			t.Errorf("[%d] line: %s, expected %t, actual %t", i, tt.in, tt.found, found)
		}
		if tt.out != d {
			t.Errorf("[%d] line: %s, expected %v, actual %v", i, tt.in, tt.out, d)
		}
	}
}

func TestIsDescriptionLine(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in    string
		found bool
	}{
		{
			"Description : Package updates are available for Amazon Linux AMI that fix the",
			true,
		},
		{
			"  Description : Package updates are available for Amazon Linux AMI that fix the",
			true,
		},
		{
			"Status : final",
			false,
		},
	}

	for i, tt := range tests {
		found := r.isDescriptionLine(tt.in)
		if tt.found != found {
			t.Errorf("[%d] line: %s, expected %t, actual %t", i, tt.in, tt.found, found)
		}
	}
}

func TestParseYumUpdateinfoToGetSeverity(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in    string
		out   string
		found bool
	}{
		{
			"Severity : Moderate",
			"Moderate",
			true,
		},
		{
			"   Severity : medium",
			"medium",
			true,
		},
		{
			"Status : final",
			"",
			false,
		},
	}

	for i, tt := range tests {
		out, found := r.parseYumUpdateinfoToGetSeverity(tt.in)
		if tt.found != found {
			t.Errorf("[%d] line: %s, expected %t, actual %t", i, tt.in, tt.found, found)
		}
		if tt.out != out {
			t.Errorf("[%d] line: %s, expected %v, actual %v", i, tt.in, tt.out, out)
		}
	}
}

func TestParseYumUpdateinfoOL(t *testing.T) {
	stdout := `===============================================================================
   bind security update
===============================================================================
  Update ID : ELSA-2017-0276
    Release : Oracle Linux 7
       Type : security
     Status : final
     Issued : 2017-02-15
       CVEs : CVE-2017-3135
Description : [32:9.9.4-38.2]
   Severity : Moderate

===============================================================================
   openssl security update
===============================================================================
  Update ID : ELSA-2017-0286
    Release : Oracle Linux 7
       Type : security
     Status : final
     Issued : 2017-02-15
       CVEs : CVE-2016-8610
	    : CVE-2017-3731
Description : [1.0.1e-48.4]
   Severity : Moderate

===============================================================================
   Unbreakable Enterprise kernel security update
===============================================================================
  Update ID : ELSA-2017-3520
    Release : Oracle Linux 7
       Type : security
     Status : final
     Issued : 2017-02-15
       CVEs : CVE-2017-6074
Description : kernel-uek
   Severity : Important

	`
	issued, _ := time.Parse("2006-01-02", "2017-02-15")

	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "oraclelinux"}

	var tests = []struct {
		in  string
		out []distroAdvisoryCveIDs
	}{
		{
			stdout,
			[]distroAdvisoryCveIDs{
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "ELSA-2017-0276",
						Severity:    "Moderate",
						Issued:      issued,
						Description: "[32:9.9.4-38.2]\n",
					},
					CveIDs: []string{"CVE-2017-3135"},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "ELSA-2017-0286",
						Severity:    "Moderate",
						Issued:      issued,
						Description: "[1.0.1e-48.4]\n",
					},
					CveIDs: []string{
						"CVE-2016-8610",
						"CVE-2017-3731",
					},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "ELSA-2017-3520",
						Severity:    "Important",
						Issued:      issued,
						Description: "kernel-uek\n",
					},
					CveIDs: []string{"CVE-2017-6074"},
				},
			},
		},
	}
	for _, tt := range tests {
		actual, _ := r.parseYumUpdateinfo(tt.in)
		for i, advisoryCveIDs := range actual {
			if tt.out[i].DistroAdvisory != advisoryCveIDs.DistroAdvisory {
				t.Errorf("[%d] Alas is not same. \nexpected: %s\nactual: %s",
					i, tt.out[i].DistroAdvisory, advisoryCveIDs.DistroAdvisory)
			}
			sort.Strings(tt.out[i].CveIDs)
			sort.Strings(advisoryCveIDs.CveIDs)
			if !reflect.DeepEqual(tt.out[i].CveIDs, advisoryCveIDs.CveIDs) {
				t.Errorf("[%d] Alas is not same. \nexpected: %s\nactual: %s",
					i, tt.out[i].CveIDs, advisoryCveIDs.CveIDs)
			}
		}
	}
}

func TestParseYumUpdateinfoRHEL(t *testing.T) {

	stdout := `===============================================================================
  Important: bind security update
===============================================================================
  Update ID : RHSA-2015:1705
    Release :
       Type : security
     Status : final
     Issued : 2015-09-03 00:00:00
       Bugs : 1259087 - CVE-2015-5722 bind: malformed DNSSEC key failed assertion denial of service
       CVEs : CVE-2015-5722
Description : The Berkeley Internet Name Domain (BIND) is an implementation of
   Severity : Important

===============================================================================
  Important: bind security update
===============================================================================
  Update ID : RHSA-2015:2655
    Release :
       Type : security
     Status : final
     Issued : 2015-09-03 01:00:00
    Updated : 2015-09-04 00:00:00
       Bugs : 1291176 - CVE-2015-8000 bind: responses with a malformed class attribute can trigger an assertion failure in db.c
       CVEs : CVE-2015-8000
            : CVE-2015-8001
Description : The Berkeley Internet Name Domain (BIND) is an implementation of
   Severity : Low

===============================================================================
  Moderate: bind security update
===============================================================================
  Update ID : RHSA-2016:0073
    Release :
       Type : security
     Status : final
     Issued : 2015-09-03 02:00:00
       Bugs : 1299364 - CVE-2015-8704 bind: specific APL data could trigger an INSIST in apl_42.c
	   CVEs : CVE-2015-8704
	        : CVE-2015-8705
Description : The Berkeley Internet Name Domain (BIND) is an implementation of
	        : CVE-2015-10000
   Severity : Moderate

===============================================================================
  Moderate: sudo security update
===============================================================================
  Update ID : RHSA-2017:1574
    Release : 0
       Type : security
     Status : final
     Issued : 2015-09-03 02:00:00
       Bugs : 1459152 - CVE-2017-1000368 sudo: Privilege escalation via improper get_process_ttyname() parsing (insufficient fix for CVE-2017-1000367)       CVEs : CVE-2017-1000368
Description : The sudo packages contain the sudo utility which allows system
            : administrators to provide certain users with the
   Severity : Moderate
	`
	issued, _ := time.Parse("2006-01-02", "2015-09-03")
	updated, _ := time.Parse("2006-01-02", "2015-09-04")

	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "redhat"}

	var tests = []struct {
		in  string
		out []distroAdvisoryCveIDs
	}{
		{
			stdout,
			[]distroAdvisoryCveIDs{
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "RHSA-2015:1705",
						Severity:    "Important",
						Issued:      issued,
						Description: "The Berkeley Internet Name Domain (BIND) is an implementation of\n",
					},
					CveIDs: []string{"CVE-2015-5722"},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "RHSA-2015:2655",
						Severity:    "Low",
						Issued:      issued,
						Updated:     updated,
						Description: "The Berkeley Internet Name Domain (BIND) is an implementation of\n",
					},
					CveIDs: []string{
						"CVE-2015-8000",
						"CVE-2015-8001",
					},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "RHSA-2016:0073",
						Severity:    "Moderate",
						Issued:      issued,
						Description: "The Berkeley Internet Name Domain (BIND) is an implementation of\nCVE-2015-10000\n",
					},
					CveIDs: []string{
						"CVE-2015-8704",
						"CVE-2015-8705",
					},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "RHSA-2017:1574",
						Severity:    "Moderate",
						Issued:      issued,
						Description: "The sudo packages contain the sudo utility which allows system\nadministrators to provide certain users with the\n",
					},
					CveIDs: []string{
						"CVE-2017-1000368",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		actual, _ := r.parseYumUpdateinfo(tt.in)
		for i, advisoryCveIDs := range actual {
			sort.Strings(tt.out[i].CveIDs)
			sort.Strings(advisoryCveIDs.CveIDs)
			if !reflect.DeepEqual(tt.out[i], advisoryCveIDs) {
				e := pp.Sprintf("%v", tt.out[i])
				a := pp.Sprintf("%v", advisoryCveIDs)
				t.Errorf("[%d] not same. \nexpected: %s\nactual: %s",
					i, e, a)
			}
		}
	}
}

func TestParseYumUpdateinfoAmazon(t *testing.T) {

	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "redhat"}

	issued, _ := time.Parse("2006-01-02", "2015-12-15")
	// updated, _ := time.Parse("2006-01-02", "2015-12-16")

	var tests = []struct {
		in  string
		out []distroAdvisoryCveIDs
	}{
		{
			`===============================================================================
  Amazon Linux AMI 2014.03 - ALAS-2016-644: medium priority package update for python-rsa
===============================================================================
  Update ID : ALAS-2016-644
    Release :
       Type : security
     Status : final
     Issued : 2015-12-15 13:30
       CVEs : CVE-2016-1494
Description : Package updates are available for Amazon Linux AMI that fix the
            : CVE-20160-1111
            : hogehoge
   Severity : medium

===============================================================================
  Amazon Linux AMI 2014.03 - ALAS-2015-614: medium priority package update for openssl
===============================================================================
  Update ID : ALAS-2015-614
    Release :
       Type : security
     Status : final
     Issued : 2015-12-15 10:00
    Updated : 2015-12-16 14:15       CVEs : CVE-2015-3194
            : CVE-2015-3195
            : CVE-2015-3196
Description : Package updates are available for Amazon Linux AMI that fix the
            : foo bar baz
            : hoge fuga hega
   Severity : medium`,

			[]distroAdvisoryCveIDs{
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "ALAS-2016-644",
						Severity:    "medium",
						Issued:      issued,
						Description: "Package updates are available for Amazon Linux AMI that fix the\nCVE-20160-1111\nhogehoge\n",
					},
					CveIDs: []string{"CVE-2016-1494"},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID:  "ALAS-2015-614",
						Severity:    "medium",
						Issued:      issued,
						Description: "Package updates are available for Amazon Linux AMI that fix the\nfoo bar baz\nhoge fuga hega\n",
					},
					CveIDs: []string{
						"CVE-2015-3194",
						"CVE-2015-3195",
						"CVE-2015-3196",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		actual, _ := r.parseYumUpdateinfo(tt.in)
		for i, advisoryCveIDs := range actual {
			sort.Strings(tt.out[i].CveIDs)
			sort.Strings(actual[i].CveIDs)
			if !reflect.DeepEqual(tt.out[i], advisoryCveIDs) {
				e := pp.Sprintf("%v", tt.out[i])
				a := pp.Sprintf("%v", advisoryCveIDs)
				t.Errorf("[%d] Alas is not same. expected %s, actual %s",
					i, e, a)
			}
		}
	}
}

func TestParseYumCheckUpdateLine(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "centos"}
	var tests = []struct {
		in  string
		out models.Package
	}{
		{
			"zlib 0 1.2.7 17.el7 rhui-REGION-rhel-server-releases",
			models.Package{
				Name:       "zlib",
				NewVersion: "1.2.7",
				NewRelease: "17.el7",
				Repository: "rhui-REGION-rhel-server-releases",
			},
		},
		{
			"shadow-utils 2 4.1.5.1 24.el7 rhui-REGION-rhel-server-releases",
			models.Package{
				Name:       "shadow-utils",
				NewVersion: "2:4.1.5.1",
				NewRelease: "24.el7",
				Repository: "rhui-REGION-rhel-server-releases",
			},
		},
	}

	for _, tt := range tests {
		aPack, err := r.parseUpdatablePacksLine(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
			return
		}
		if !reflect.DeepEqual(tt.out, aPack) {
			e := pp.Sprintf("%v", tt.out)
			a := pp.Sprintf("%v", aPack)
			t.Errorf("expected %s, actual %s", e, a)
		}
	}
}

func TestParseYumCheckUpdateLines(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "centos"}
	stdout := `audit-libs 0 2.3.7 5.el6 base
bash 0 4.1.2 33.el6_7.1 updates
python-libs 0 2.6.6 64.el6 rhui-REGION-rhel-server-releases
python-ordereddict 0 1.1 3.el6ev installed
bind-utils 30 9.3.6 25.P1.el5_11.8 updates
pytalloc 0 2.0.7 2.el6 @CentOS 6.5/6.5`

	r.Packages = models.NewPackages(
		models.Package{Name: "audit-libs"},
		models.Package{Name: "bash"},
		models.Package{Name: "python-libs"},
		models.Package{Name: "python-ordereddict"},
		models.Package{Name: "bind-utils"},
		models.Package{Name: "pytalloc"},
	)
	var tests = []struct {
		in  string
		out models.Packages
	}{
		{
			stdout,
			models.NewPackages(
				models.Package{
					Name:       "audit-libs",
					NewVersion: "2.3.7",
					NewRelease: "5.el6",
					Repository: "base",
				},
				models.Package{
					Name:       "bash",
					NewVersion: "4.1.2",
					NewRelease: "33.el6_7.1",
					Repository: "updates",
				},
				models.Package{
					Name:       "python-libs",
					NewVersion: "2.6.6",
					NewRelease: "64.el6",
					Repository: "rhui-REGION-rhel-server-releases",
				},
				models.Package{
					Name:       "python-ordereddict",
					NewVersion: "1.1",
					NewRelease: "3.el6ev",
					Repository: "installed",
				},
				models.Package{
					Name:       "bind-utils",
					NewVersion: "30:9.3.6",
					NewRelease: "25.P1.el5_11.8",
					Repository: "updates",
				},
				models.Package{
					Name:       "pytalloc",
					NewVersion: "2.0.7",
					NewRelease: "2.el6",
					Repository: "@CentOS 6.5/6.5",
				},
			),
		},
	}

	for _, tt := range tests {
		packages, err := r.parseUpdatablePacksLines(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
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

func TestParseYumCheckUpdateLinesAmazon(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "amazon"}
	stdout := `bind-libs 32 9.8.2 0.37.rc1.45.amzn1 amzn-main
java-1.7.0-openjdk  0 1.7.0.95 2.6.4.0.65.amzn1 amzn-main
if-not-architecture 0 100 200 amzn-main`
	r.Packages = models.NewPackages(
		models.Package{Name: "bind-libs"},
		models.Package{Name: "java-1.7.0-openjdk"},
		models.Package{Name: "if-not-architecture"},
	)
	var tests = []struct {
		in  string
		out models.Packages
	}{
		{
			stdout,
			models.NewPackages(
				models.Package{
					Name:       "bind-libs",
					NewVersion: "32:9.8.2",
					NewRelease: "0.37.rc1.45.amzn1",
					Repository: "amzn-main",
				},
				models.Package{
					Name:       "java-1.7.0-openjdk",
					NewVersion: "1.7.0.95",
					NewRelease: "2.6.4.0.65.amzn1",
					Repository: "amzn-main",
				},
				models.Package{
					Name:       "if-not-architecture",
					NewVersion: "100",
					NewRelease: "200",
					Repository: "amzn-main",
				},
			),
		},
	}

	for _, tt := range tests {
		packages, err := r.parseUpdatablePacksLines(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
			return
		}
		for name, ePack := range tt.out {
			if !reflect.DeepEqual(ePack, packages[name]) {
				e := pp.Sprintf("%v", ePack)
				a := pp.Sprintf("%v", packages[name])
				t.Errorf("[%s] expected %s, actual %s", name, e, a)
			}
		}
	}
}

func TestParseYumUpdateinfoListAvailable(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	rhelStdout := `RHSA-2015:2315 Moderate/Sec.  NetworkManager-1:1.0.6-27.el7.x86_64
RHSA-2015:2315 Moderate/Sec.  NetworkManager-config-server-1:1.0.6-27.el7.x86_64
RHSA-2015:1705 Important/Sec. bind-libs-lite-32:9.9.4-18.el7_1.5.x86_64
RHSA-2016:0176 Critical/Sec.  glibc-2.17-106.el7_2.4.x86_64
RHSA-2015:2401 Low/Sec.       grub2-1:2.02-0.29.el7.x86_64
RHSA-2015:2401 Low/Sec.       grub2-tools-1:2.02-0.29.el7.x86_64
updateinfo list done`

	var tests = []struct {
		in  string
		out []advisoryIDPacks
	}{
		{
			rhelStdout,
			[]advisoryIDPacks{
				{
					AdvisoryID: "RHSA-2015:2315",
					PackNames: []string{
						"NetworkManager",
						"NetworkManager-config-server",
					},
				},
				{
					AdvisoryID: "RHSA-2015:1705",
					PackNames: []string{
						"bind-libs-lite",
					},
				},
				{
					AdvisoryID: "RHSA-2016:0176",
					PackNames: []string{
						"glibc",
					},
				},
				{
					AdvisoryID: "RHSA-2015:2401",
					PackNames: []string{
						"grub2",
						"grub2-tools",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		actual, err := r.parseYumUpdateinfoListAvailable(tt.in)
		if err != nil {
			t.Errorf("Error has occurred: %s", err)
			return
		}

		for i := range actual {
			if !reflect.DeepEqual(actual[i], tt.out[i]) {
				e := pp.Sprintf("%v", tt.out)
				a := pp.Sprintf("%v", actual)
				t.Errorf("[%d] expected: %s\nactual: %s", i, e, a)
			}
		}
	}
}

func TestExtractPackNameVerRel(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in  string
		out []string
	}{
		{
			"openssh-server-6.2p2-8.45.amzn1.x86_64",
			[]string{"openssh-server", "6.2p2", "8.45.amzn1"},
		},
		{
			"bind-libs-lite-32:9.9.4-29.el7_2.1.x86_64",
			[]string{"bind-libs-lite", "32:9.9.4", "29.el7_2.1"},
		},
		{
			"glibc-2.17-106.el7_2.1.x86_64",
			[]string{"glibc", "2.17", "106.el7_2.1"},
		},
	}

	for _, tt := range tests {
		name, ver, rel := r.extractPackNameVerRel(tt.in)
		if tt.out[0] != name {
			t.Errorf("name: expected %s, actual %s", tt.out[0], name)
		}
		if tt.out[1] != ver {
			t.Errorf("ver: expected %s, actual %s", tt.out[1], ver)
		}
		if tt.out[2] != rel {
			t.Errorf("ver: expected %s, actual %s", tt.out[2], rel)
		}
	}

}

func TestGetDiffChangelog(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	type in struct {
		pack      models.Package
		changelog string
	}

	var tests = []struct {
		in  in
		out string
	}{
		// 0
		{
			in: in{
				pack: models.Package{
					Version: "2017a",
					Release: "1",
				},
				changelog: `* Mon Mar 20 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> - 2017b-1
- Rebase to tzdata-2017b.
  - Haiti resumed DST on March 12, 2017.

* Thu Mar  2 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> - 2017a-1
- Rebase to tzdata-2017a
  - Mongolia no longer observes DST. (BZ #1425222)
  - Add upstream patch to fix over-runing of POSIX limit on zone abbreviations.
- Add zone1970.tab file to the install list. (BZ #1427694)

* Wed Nov 23 12:00:00 2016 Patsy Franklin <pfrankli@redhat.com> - 2016j-1
- Rebase to tzdata-2016ij
  - Saratov region of Russia is moving from +03 offset to +04 offset
    on 2016-12-04.`,
			},
			out: `* Mon Mar 20 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> - 2017b-1
- Rebase to tzdata-2017b.
  - Haiti resumed DST on March 12, 2017.`,
		},
		// 1
		{
			in: in{
				pack: models.Package{
					Version: "2004e",
					Release: "2",
				},
				changelog: `* Mon Mar 20 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> - 2017b-1
- Rebase to tzdata-2017b.
  - Haiti resumed DST on March 12, 2017.

* Wed Nov 23 12:00:00 2016 Patsy Franklin <pfrankli@redhat.com> - 2016j-1
- Rebase to tzdata-2016ij
  - Saratov region of Russia is moving from +03 offset to +04 offset
    on 2016-12-04.

* Mon Nov 29 12:00:00 2004 Jakub Jelinek <jakub@redhat.com> 2004g-1
- 2004g (#141107)
- updates for Cuba

* Mon Oct 11 12:00:00 2004 Jakub Jelinek <jakub@redhat.com> 2004e-2
- 2004e (#135194)
- updates for Brazil, Uruguay and Argentina`,
			},
			out: `* Mon Mar 20 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> - 2017b-1
- Rebase to tzdata-2017b.
  - Haiti resumed DST on March 12, 2017.

* Wed Nov 23 12:00:00 2016 Patsy Franklin <pfrankli@redhat.com> - 2016j-1
- Rebase to tzdata-2016ij
  - Saratov region of Russia is moving from +03 offset to +04 offset
    on 2016-12-04.

* Mon Nov 29 12:00:00 2004 Jakub Jelinek <jakub@redhat.com> 2004g-1
- 2004g (#141107)
- updates for Cuba`,
		},
		// 2
		{
			in: in{
				pack: models.Package{
					Version: "2016j",
					Release: "1",
				},
				changelog: `* Mon Mar 20 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> -2017b-1
- Rebase to tzdata-2017b.
  - Haiti resumed DST on March 12, 2017.

* Wed Nov 23 12:00:00 2016 Patsy Franklin <pfrankli@redhat.com> -2016j-1
- Rebase to tzdata-2016ij
  - Saratov region of Russia is moving from +03 offset to +04 offset
    on 2016-12-04.`,
			},
			out: `* Mon Mar 20 12:00:00 2017 Patsy Franklin <pfrankli@redhat.com> -2017b-1
- Rebase to tzdata-2017b.
  - Haiti resumed DST on March 12, 2017.`,
		},
		// 3
		{
			in: in{
				pack: models.Package{
					Version: "3.10.0",
					Release: "327.22.1.el7",
				},
				changelog: `* Thu Jun  9 21:00:00 2016 Alexander Gordeev <agordeev@redhat.com> [3.10.0-327.22.2.el7]
- [infiniband] security: Restrict use of the write() interface (Don Dutile) [1332553 1316685] {CVE-2016-4565}

* Mon May 16 21:00:00 2016 Alexander Gordeev <agordeev@redhat.com> [3.10.0-327.22.1.el7]
- [mm] mmu_notifier: fix memory corruption (Jerome Glisse) [1335727 1307042]
- [misc] cxl: Increase timeout for detection of AFU mmio hang (Steve Best) [1335419 1329682]
- [misc] cxl: Configure the PSL for two CAPI ports on POWER8NVL (Steve Best) [1336389 1278793]`,
			},
			out: `* Thu Jun  9 21:00:00 2016 Alexander Gordeev <agordeev@redhat.com> [3.10.0-327.22.2.el7]
- [infiniband] security: Restrict use of the write() interface (Don Dutile) [1332553 1316685] {CVE-2016-4565}`,
		},
		// 4
		{
			in: in{
				pack: models.Package{
					Version: "6.6.1p1",
					Release: "34",
				},

				changelog: `* Wed Mar  1 21:00:00 2017 Jakub Jelen <jjelen@redhat.com> - 6.6.1p1-35 + 0.9.3-9
- Do not send SD_NOTIFY from forked childern (#1381997)

* Fri Feb 24 21:00:00 2017 Jakub Jelen <jjelen@redhat.com> - 6.6.1p1-34 + 0.9.3-9
- Add SD_NOTIFY code to help systemd to track running service (#1381997)`,
			},
			out: `* Wed Mar  1 21:00:00 2017 Jakub Jelen <jjelen@redhat.com> - 6.6.1p1-35
- Do not send SD_NOTIFY from forked childern (#1381997)`,
		},
		// 5
		{
			in: in{
				pack: models.Package{
					Version: "2.1.23",
					Release: "15.el6",
				},
				changelog: `* Fri Feb 27 12:00:00 2015 Jakub Jelen <jjelen@redhat.com> 2.1.23-15.2
- Support AIX SASL GSSAPI (#1174315)

* Tue Nov 18 12:00:00 2014 Petr Lautrbach <plautrba@redhat.com> 2.1.23-15.1
- check a context value in sasl_gss_encode() (#1087221)

* Mon Jun 23 12:00:00 2014 Petr Lautrbach <plautrba@redhat.com> 2.1.23-15
- don't use " for saslauth user's description (#1081445)
- backport the ad_compat option (#994242)
- fixed a memory leak in the client side DIGEST-MD5 code (#838628)`,
			},
			out: `* Fri Feb 27 12:00:00 2015 Jakub Jelen <jjelen@redhat.com> 2.1.23-15.2
- Support AIX SASL GSSAPI (#1174315)

* Tue Nov 18 12:00:00 2014 Petr Lautrbach <plautrba@redhat.com> 2.1.23-15.1
- check a context value in sasl_gss_encode() (#1087221)`,
		},
		// 6
		{
			in: in{
				pack: models.Package{
					Version: "3.6.20",
					Release: "1.el6",
				},
				changelog: `* Wed Jul 29 12:00:00 2015 Jan Stanek <jstanek@redhat.com> - 3.6.20-1.2
- Add patch for compiler warnings highlighted by rpmdiff.
  Related: rhbz#1244727

* Wed Jul 22 12:00:00 2015 Viktor Jancik <vjancik@redhat.com> - 3.6.20-1.el6_7.1
- fix for CVE-2015-3416
  Resolves: #1244727

* Tue Nov 17 12:00:00 2009 Panu Matilainen <pmatilai@redhat.com> - 3.6.20-1
- update to 3.6.20 (http://www.sqlite.org/releaselog/3_6_20.html)

* Tue Oct  6 12:00:00 2009 Panu Matilainen <pmatilai@redhat.com> - 3.6.18-1
- update to 3.6.18 (http://www.sqlite.org/releaselog/3_6_18.html)
- drop no longer needed test-disabler patches`,
			},
			out: `* Wed Jul 29 12:00:00 2015 Jan Stanek <jstanek@redhat.com> - 3.6.20-1.2
- Add patch for compiler warnings highlighted by rpmdiff.
  Related: rhbz#1244727

* Wed Jul 22 12:00:00 2015 Viktor Jancik <vjancik@redhat.com> - 3.6.20-1.el6_7.1
- fix for CVE-2015-3416
  Resolves: #1244727`,
		},
		/*
					// 7
					{
						in: in{
							pack: models.Package{
								Version: "2:7.4.160",
								Release: "1.el7",
							},
							changelog: `* Mon Dec 12 21:00:00 2016 Karsten Hopp <karsten@redhat.com> 7.4.160-1.1
			- add fix for CVE-2016-1248

			* Wed Jan 29 21:00:00 2014 Karsten Hopp <karsten@redhat.com> 7.4.160-1
			- patchlevel 160
			- Resolves: rhbz#1059321`,
						},
						out: `* Mon Dec 12 21:00:00 2016 Karsten Hopp <karsten@redhat.com> 7.4.160-1.1
			- add fix for CVE-2016-1248`,
					},
					// 8
					{
						in: in{
							pack: models.Package{
								Version: "2:1.26",
								Release: "29.el7",
							},
							changelog: `* Mon Jun 20 21:00:00 2016 Pavel Raiskup <praiskup@redhat.com> - 1.26-31
			- avoid double free in selinux code (rhbz#1347396)

			* Thu Jun  4 21:00:00 2015 Pavel Raiskup <praiskup@redhat.com> - 1.26-30
			- don't mistakenly set default ACLs (#1220890)

			* Fri Jan 24 21:00:00 2014 Daniel Mach <dmach@redhat.com> - 2:1.26-29
			- Mass rebuild 2014-01-24`,
						},
						out: `* Mon Jun 20 21:00:00 2016 Pavel Raiskup <praiskup@redhat.com> - 1.26-31
			- avoid double free in selinux code (rhbz#1347396)

			* Thu Jun  4 21:00:00 2015 Pavel Raiskup <praiskup@redhat.com> - 1.26-30
			- don't mistakenly set default ACLs (#1220890)`,
					},
					// 9
					{
						in: in{
							pack: models.Package{
								Version: "1:1.0.1e",
								Release: "51.el7_2.5",
							},
							changelog: `* Mon Feb  6 21:00:00 2017 Tomáš Mráz <tmraz@redhat.com> 1.0.1e-60.1
			- fix CVE-2017-3731 - DoS via truncated packets with RC4-MD5 cipher
			- fix CVE-2016-8610 - DoS of single-threaded servers via excessive alerts

			* Fri Dec  4 21:00:00 2015 Tomáš Mráz <tmraz@redhat.com> 1.0.1e-52
			- fix CVE-2015-3194 - certificate verify crash with missing PSS parameter
			- fix CVE-2015-3195 - X509_ATTRIBUTE memory leak
			- fix CVE-2015-3196 - race condition when handling PSK identity hint

			* Tue Jun 23 21:00:00 2015 Tomáš Mráz <tmraz@redhat.com> 1.0.1e-51
			- fix the CVE-2015-1791 fix (broken server side renegotiation)`,
						},
						out: `* Mon Feb  6 21:00:00 2017 Tomáš Mráz <tmraz@redhat.com> 1.0.1e-60.1
			- fix CVE-2017-3731 - DoS via truncated packets with RC4-MD5 cipher
			- fix CVE-2016-8610 - DoS of single-threaded servers via excessive alerts

			* Fri Dec  4 21:00:00 2015 Tomáš Mráz <tmraz@redhat.com> 1.0.1e-52
			- fix CVE-2015-3194 - certificate verify crash with missing PSS parameter
			- fix CVE-2015-3195 - X509_ATTRIBUTE memory leak
			- fix CVE-2015-3196 - race condition when handling PSK identity hint`,
					},
					// 10
					{
						in: in{
							pack: models.Package{
								Version: "1:5.5.47",
								Release: "1.el7_2",
							},
							changelog: `* Wed Sep 21 21:00:00 2016 Honza Horak <hhorak@redhat.com> - 5.5.52-1
			- Rebase to 5.5.52, that also include fix for CVE-2016-6662
			  Resolves: #1377974

			* Thu Feb 18 21:00:00 2016 Jakub Dorňák <jdornak@redhat.com> - 1:5.5.47-2
			- Add warning to /usr/lib/tmpfiles.d/mariadb.conf
			  Resolves: #1241623

			* Wed Feb  3 21:00:00 2016 Jakub Dorňák <jdornak@redhat.com> - 1:5.5.47-1
			- Rebase to 5.5.47
			  Also fixes: CVE-2015-4792 CVE-2015-4802 CVE-2015-4815 CVE-2015-4816
			  CVE-2015-4819 CVE-2015-4826 CVE-2015-4830 CVE-2015-4836 CVE-2015-4858
			  CVE-2015-4861 CVE-2015-4870 CVE-2015-4879 CVE-2015-4913 CVE-2015-7744
			  CVE-2016-0505 CVE-2016-0546 CVE-2016-0596 CVE-2016-0597 CVE-2016-0598
			  CVE-2016-0600 CVE-2016-0606 CVE-2016-0608 CVE-2016-0609 CVE-2016-0616
			  CVE-2016-2047
			  Resolves: #1300621`,
						},
						out: `* Wed Sep 21 21:00:00 2016 Honza Horak <hhorak@redhat.com> - 5.5.52-1
			- Rebase to 5.5.52, that also include fix for CVE-2016-6662
			  Resolves: #1377974

			* Thu Feb 18 21:00:00 2016 Jakub Dorňák <jdornak@redhat.com> - 1:5.5.47-2
			- Add warning to /usr/lib/tmpfiles.d/mariadb.conf
			  Resolves: #1241623`,
					},
		*/
		// 11
		{
			in: in{
				pack: models.Package{
					Version: "0.252",
					Release: "8.1.el7",
				},
				changelog: `* Thu Sep 29 21:00:00 2016 Vitezslav Crhonek <vcrhonek@redhat.com> - 0.252-8.4
- Remove wrong entry from usb ids.
  Resolves: #1380159

* Mon Sep 26 21:00:00 2016 Vitezslav Crhonek <vcrhonek@redhat.com> - 0.252-8.3
- Updated pci, usb and vendor ids.
- Resolves: rhbz#1292382

* Tue Jun 28 21:00:00 2016 Michal Minar <miminar@redhat.com> 0.252-8.2
- Updated pci, usb and vendor ids.
- Resolves: rhbz#1292382
- Resolves: rhbz#1291614
- Resolves: rhbz#1324198

* Fri Oct 23 21:00:00 2015 Michal Minar <miminar@redhat.com> 0.252-8.1
- Updated pci, usb and vendor ids.`,
			},
			out: `* Thu Sep 29 21:00:00 2016 Vitezslav Crhonek <vcrhonek@redhat.com> - 0.252-8.4
- Remove wrong entry from usb ids.
  Resolves: #1380159

* Mon Sep 26 21:00:00 2016 Vitezslav Crhonek <vcrhonek@redhat.com> - 0.252-8.3
- Updated pci, usb and vendor ids.
- Resolves: rhbz#1292382

* Tue Jun 28 21:00:00 2016 Michal Minar <miminar@redhat.com> 0.252-8.2
- Updated pci, usb and vendor ids.
- Resolves: rhbz#1292382
- Resolves: rhbz#1291614
- Resolves: rhbz#1324198`,
		},
		// 12
		{
			in: in{
				pack: models.Package{
					Version: "1:2.02",
					Release: "0.34.el7_2",
				},
				changelog: `* Mon Aug 29 21:00:00 2016 Peter Jones <pjones@redhat.com> - 2.02-0.44
- Work around tftp servers that don't work with multiple consecutive slashes in
  file paths.
  Resolves: rhbz#1217243`,
			},
			out: `* Mon Aug 29 21:00:00 2016 Peter Jones <pjones@redhat.com> - 2.02-0.44
- Work around tftp servers that don't work with multiple consecutive slashes in
  file paths.
  Resolves: rhbz#1217243`,
		},
	}

	for i, tt := range tests {
		diff, _ := r.getDiffChangelog(tt.in.pack, tt.in.changelog)
		if tt.out != diff {
			t.Errorf("[%d] name: expected \n%s\nactual \n%s", i, tt.out, diff)
		}
	}

}

func TestDivideChangelogsIntoEachPackages(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	type in struct {
		pack      models.Package
		changelog string
	}

	var tests = []struct {
		in  string
		out map[string]string
	}{
		{
			in: `==================== Available Packages ====================
1:NetworkManager-1.4.0-20.el7_3.x86_64   rhui-rhel-7-server-rhui-rpms
* Mon Apr 24 21:00:00 2017 Beniamino Galvani <bgalvani@redhat.com> - 1:1.4.0-20
- vlan: use parent interface mtu as default (rh#1414186)

* Wed Mar 29 21:00:00 2017 Beniamino Galvani <bgalvani@redhat.com> - 1:1.4.0-19
- core: alyways force a sync of the default route (rh#1431268)


1:NetworkManager-0.9.9.1-25.git20140326. rhui-rhel-7-server-rhui-optional-rpms
* Tue Jul  1 21:00:00 2014 Jiří Klimeš <jklimes@redhat.com> - 1:0.9.9.1-25.git20140326
- core: fix MTU handling while merging/subtracting IP configs (rh #1093231)

* Mon Jun 23 21:00:00 2014 Thomas Haller <thaller@redhat.com> - 1:0.9.9.1-24.git20140326
- core: fix crash on failure of reading bridge sysctl values (rh #1112020)`,
			out: map[string]string{
				"1:NetworkManager-1.4.0-20.el7_3.x86_64": `* Mon Apr 24 21:00:00 2017 Beniamino Galvani <bgalvani@redhat.com> - 1:1.4.0-20
- vlan: use parent interface mtu as default (rh#1414186)

* Wed Mar 29 21:00:00 2017 Beniamino Galvani <bgalvani@redhat.com> - 1:1.4.0-19
- core: alyways force a sync of the default route (rh#1431268)`,

				"1:NetworkManager-0.9.9.1-25.git20140326.": `* Tue Jul  1 21:00:00 2014 Jiří Klimeš <jklimes@redhat.com> - 1:0.9.9.1-25.git20140326
- core: fix MTU handling while merging/subtracting IP configs (rh #1093231)

* Mon Jun 23 21:00:00 2014 Thomas Haller <thaller@redhat.com> - 1:0.9.9.1-24.git20140326
- core: fix crash on failure of reading bridge sysctl values (rh #1112020)`,
			},
		},
	}

	for _, tt := range tests {
		changelogs := r.divideChangelogsIntoEachPackages(tt.in)
		for k, v := range tt.out {
			if strings.TrimSpace(v) != strings.TrimSpace(changelogs[k]) {
				t.Errorf("expected: %v\nactual: %v", pp.Sprint(tt.out), pp.Sprint(changelogs))
			}
		}
	}

}
