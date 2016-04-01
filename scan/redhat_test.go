/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package scan

import (
	"reflect"
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
		pack models.PackageInfo
	}{
		{
			"openssl	1.0.1e	30.el6.11",
			models.PackageInfo{
				Name:    "openssl",
				Version: "1.0.1e",
				Release: "30.el6.11",
			},
		},
	}

	for _, tt := range packagetests {
		p, _ := r.parseScanedPackagesLine(tt.in)
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

func TestParseYumUpdateinfoHeader(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in  string
		out []models.PackageInfo
	}{
		{
			"     nodejs-0.10.36-3.el6,libuv-0.10.34-1.el6,v8-3.14.5.10-17.el6    ",
			[]models.PackageInfo{
				{
					Name:    "nodejs",
					Version: "0.10.36",
					Release: "3.el6",
				},
				{
					Name:    "libuv",
					Version: "0.10.34",
					Release: "1.el6",
				},
				{
					Name:    "v8",
					Version: "3.14.5.10",
					Release: "17.el6",
				},
			},
		},
	}

	for _, tt := range tests {
		if a, err := r.parseYumUpdateinfoHeaderCentOS(tt.in); err != nil {
			t.Errorf("err: %s", err)
		} else {
			if !reflect.DeepEqual(a, tt.out) {
				e := pp.Sprintf("%#v", tt.out)
				a := pp.Sprintf("%#v", a)
				t.Errorf("expected %s, actual %s", e, a)
			}
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
			": 1195457 - nodejs-0.10.35 causes undefined symbolsCVE-2015-0278, CVE-2015-0278, CVE-2015-0277",
			[]string{
				"CVE-2015-0278",
				"CVE-2015-0278",
				"CVE-2015-0277",
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
            : the Domain Name System (DNS) protocols. BIND
            : includes a DNS server (named); a resolver library
            : (routines for applications to use when interfacing
            : with DNS); and tools for verifying that the DNS
            : server is operating correctly.
            :
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
            : the Domain Name System (DNS) protocols. BIND
            : includes a DNS server (named); a resolver library
            : (routines for applications to use when interfacing
            : with DNS); and tools for verifying that the DNS
            : server is operating correctly.
            :
   Severity : Low

===============================================================================
  Moderate: bind security update
===============================================================================
  Update ID : RHSA-2016:0073
    Release :
       Type : security
     Status : final
     Issued : 2015-09-03 02:00:00
       Bugs : 1299364 - CVE-2015-8704 bind: specific APL data could trigger an INSIST in apl_42.c      CVEs : CVE-2015-8704
	        : CVE-2015-8705
Description : The Berkeley Internet Name Domain (BIND) is an implementation of
            : the Domain Name System (DNS) protocols. BIND
            : includes a DNS server (named); a resolver library
            : (routines for applications to use when interfacing
            : with DNS); and tools for verifying that the DNS
            : server is operating correctly.
            :
   Severity : Moderate

	`
	issued, _ := time.Parse("2006-01-02", "2015-09-03")
	updated, _ := time.Parse("2006-01-02", "2015-09-04")

	r := newRedhat(config.ServerInfo{})
	r.Family = "redhat"

	var tests = []struct {
		in  string
		out []distroAdvisoryCveIDs
	}{
		{
			stdout,
			[]distroAdvisoryCveIDs{
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "RHSA-2015:1705",
						Severity:   "Important",
						Issued:     issued,
					},
					CveIDs: []string{"CVE-2015-5722"},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "RHSA-2015:2655",
						Severity:   "Low",
						Issued:     issued,
						Updated:    updated,
					},
					CveIDs: []string{
						"CVE-2015-8000",
						"CVE-2015-8001",
					},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "RHSA-2016:0073",
						Severity:   "Moderate",
						Issued:     issued,
						Updated:    updated,
					},
					CveIDs: []string{
						"CVE-2015-8704",
						"CVE-2015-8705",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		actual, _ := r.parseYumUpdateinfo(tt.in)
		for i, advisoryCveIDs := range actual {
			if !reflect.DeepEqual(tt.out[i], advisoryCveIDs) {
				e := pp.Sprintf("%v", tt.out[i])
				a := pp.Sprintf("%v", advisoryCveIDs)
				t.Errorf("[%d] Alas is not same. \nexpected: %s\nactual: %s",
					i, e, a)
			}
		}
	}
}

func TestParseYumUpdateinfoAmazon(t *testing.T) {

	r := newRedhat(config.ServerInfo{})
	r.Family = "amazon"

	issued, _ := time.Parse("2006-01-02", "2015-12-15")
	updated, _ := time.Parse("2006-01-02", "2015-12-16")

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
            : following vulnerabilities: CVE-2016-1494:
            :         1295869:
            : CVE-2016-1494 python-rsa: Signature forgery using
            : Bleichenbacher'06 attack
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
            : following vulnerabilities: CVE-2015-3196:
            :         1288326:
            : CVE-2015-3196 OpenSSL: Race condition handling PSK
            : identify hint A race condition flaw, leading to a
            : double free, was found in the way OpenSSL handled
            : pre-shared keys (PSKs). A remote attacker could
            : use this flaw to crash a multi-threaded SSL/TLS
            : client.
            :
   Severity : medium`,

			[]distroAdvisoryCveIDs{
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "ALAS-2016-644",
						Severity:   "medium",
						Issued:     issued,
					},
					CveIDs: []string{"CVE-2016-1494"},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "ALAS-2015-614",
						Severity:   "medium",
						Issued:     issued,
						Updated:    updated,
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
			if !reflect.DeepEqual(tt.out[i], advisoryCveIDs) {
				e := pp.Sprintf("%v", tt.out[i])
				a := pp.Sprintf("%v", advisoryCveIDs)
				t.Errorf("[%d] Alas is not same. expected %s, actual %s",
					i, e, a)
			}
		}
	}
}

func TestParseYumCheckUpdateLines(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Family = "centos"
	stdout := `Loaded plugins: changelog, fastestmirror, keys, protect-packages, protectbase, security
Loading mirror speeds from cached hostfile
 * base: mirror.fairway.ne.jp
 * epel: epel.mirror.srv.co.ge
 * extras: mirror.fairway.ne.jp
 * updates: mirror.fairway.ne.jp
0 packages excluded due to repository protections

audit-libs.x86_64              2.3.7-5.el6                   base
bash.x86_64                    4.1.2-33.el6_7.1              updates
	`
	r.Packages = []models.PackageInfo{
		{
			Name:    "audit-libs",
			Version: "2.3.6",
			Release: "4.el6",
		},
		{
			Name:    "bash",
			Version: "4.1.1",
			Release: "33",
		},
	}
	var tests = []struct {
		in  string
		out models.PackageInfoList
	}{
		{
			stdout,
			models.PackageInfoList{
				{
					Name:       "audit-libs",
					Version:    "2.3.6",
					Release:    "4.el6",
					NewVersion: "2.3.7",
					NewRelease: "5.el6",
				},
				{
					Name:       "bash",
					Version:    "4.1.1",
					Release:    "33",
					NewVersion: "4.1.2",
					NewRelease: "33.el6_7.1",
				},
			},
		},
	}

	for _, tt := range tests {
		packInfoList, err := r.parseYumCheckUpdateLines(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
			return
		}
		for i, ePackInfo := range tt.out {
			if !reflect.DeepEqual(ePackInfo, packInfoList[i]) {
				e := pp.Sprintf("%v", ePackInfo)
				a := pp.Sprintf("%v", packInfoList[i])
				t.Errorf("[%d] expected %s, actual %s", i, e, a)
			}
		}
	}
}

func TestParseYumCheckUpdateLinesAmazon(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Family = "amzon"
	stdout := `Loaded plugins: priorities, update-motd, upgrade-helper
34 package(s) needed for security, out of 71 available

bind-libs.x86_64           32:9.8.2-0.37.rc1.45.amzn1      amzn-main
java-1.7.0-openjdk.x86_64  1:1.7.0.95-2.6.4.0.65.amzn1     amzn-main
if-not-architecture        100-200                         amzn-main
`
	r.Packages = []models.PackageInfo{
		{
			Name:    "bind-libs",
			Version: "32:9.8.0",
			Release: "0.33.rc1.45.amzn1",
		},
		{
			Name:    "java-1.7.0-openjdk",
			Version: "1:1.7.0.0",
			Release: "2.6.4.0.0.amzn1",
		},
		{
			Name:    "if-not-architecture",
			Version: "10",
			Release: "20",
		},
	}
	var tests = []struct {
		in  string
		out models.PackageInfoList
	}{
		{
			stdout,
			models.PackageInfoList{
				{
					Name:       "bind-libs",
					Version:    "32:9.8.0",
					Release:    "0.33.rc1.45.amzn1",
					NewVersion: "32:9.8.2",
					NewRelease: "0.37.rc1.45.amzn1",
				},
				{
					Name:       "java-1.7.0-openjdk",
					Version:    "1:1.7.0.0",
					Release:    "2.6.4.0.0.amzn1",
					NewVersion: "1:1.7.0.95",
					NewRelease: "2.6.4.0.65.amzn1",
				},
				{
					Name:       "if-not-architecture",
					Version:    "10",
					Release:    "20",
					NewVersion: "100",
					NewRelease: "200",
				},
			},
		},
	}

	for _, tt := range tests {
		packInfoList, err := r.parseYumCheckUpdateLines(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
			return
		}
		for i, ePackInfo := range tt.out {
			if !reflect.DeepEqual(ePackInfo, packInfoList[i]) {
				e := pp.Sprintf("%v", ePackInfo)
				a := pp.Sprintf("%v", packInfoList[i])
				t.Errorf("[%d] expected %s, actual %s", i, e, a)
			}
		}
	}
}

func TestParseYumUpdateinfoAmazonLinuxHeader(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in  string
		out models.DistroAdvisory
	}{
		{
			"Amazon Linux AMI 2014.03 - ALAS-2015-598: low priority package update for grep",
			models.DistroAdvisory{
				AdvisoryID: "ALAS-2015-598",
				Severity:   "low",
			},
		},
	}

	for _, tt := range tests {
		a, _, _ := r.parseYumUpdateinfoHeaderAmazon(tt.in)
		if !reflect.DeepEqual(a, tt.out) {
			e := pp.Sprintf("%v", tt.out)
			a := pp.Sprintf("%v", a)
			t.Errorf("expected %s, actual %s", e, a)
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

func TestParseYumUpdateinfoToGetUpdateID(t *testing.T) {

	r := newRedhat(config.ServerInfo{})

	var packagetests = []struct {
		in   string
		pack models.PackageInfo
	}{
		{
			"openssl	1.0.1e	30.el6.11",
			models.PackageInfo{
				Name:    "openssl",
				Version: "1.0.1e",
				Release: "30.el6.11",
			},
		},
	}

	for _, tt := range packagetests {
		p, _ := r.parseScanedPackagesLine(tt.in)
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
