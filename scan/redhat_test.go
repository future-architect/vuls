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
	"sort"
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
			"openssl	0	1.0.1e	30.el6.11",
			models.Package{
				Name:    "openssl",
				Version: "1.0.1e",
				Release: "30.el6.11",
			},
		},
		{
			"Percona-Server-shared-56	1	5.6.19	rel67.0.el6",
			models.Package{
				Name:    "Percona-Server-shared-56",
				Version: "1:5.6.19",
				Release: "rel67.0.el6",
			},
		},
	}

	for _, tt := range packagetests {
		p, _ := r.parseScannedPackagesLine(tt.in)
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

func TestIsRpmPackageNameLine(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	var tests = []struct {
		in    string
		found bool
	}{
		{
			"stunnel-4.15-2.el5.2.i386",
			true,
		},
		{
			"iproute-2.6.18-15.el5.i386",
			true,
		},
		{
			"1:yum-updatesd-0.9-6.el5_10.noarch",
			true,
		},
		{
			"glibc-2.12-1.192.el6.x86_64",
			true,
		},
		{
			" glibc-2.12-1.192.el6.x86_64",
			false,
		},
		{
			"glibc-2.12-1.192.el6.x86_64, iproute-2.6.18-15.el5.i386",
			true,
		},
		{
			"k6 hoge.i386",
			false,
		},
		{
			"triathlon",
			false,
		},
	}

	for i, tt := range tests {
		found, err := r.isRpmPackageNameLine(tt.in)
		if tt.found != found {
			t.Errorf("[%d] line: %s, expected %t, actual %t, err %v", i, tt.in, tt.found, found, err)
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
            : - Fix CVE-2017-3135 (ISC change 4557)
            : - Fix and test caching CNAME before DNAME (ISC
            :   change 4558)
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
            : - fix CVE-2017-3731 - DoS via truncated packets
            :   with RC4-MD5 cipher
            : - fix CVE-2016-8610 - DoS of single-threaded
            :   servers via excessive alerts
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
            : [4.1.12-61.1.28]
            : - dccp: fix freeing skb too early for
            :   IPV6_RECVPKTINFO (Andrey Konovalov)  [Orabug:
            :   25598257]  {CVE-2017-6074}
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
						AdvisoryID: "ELSA-2017-0276",
						Severity:   "Moderate",
						Issued:     issued,
					},
					CveIDs: []string{"CVE-2017-3135"},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "ELSA-2017-0286",
						Severity:   "Moderate",
						Issued:     issued,
					},
					CveIDs: []string{
						"CVE-2016-8610",
						"CVE-2017-3731",
					},
				},
				{
					DistroAdvisory: models.DistroAdvisory{
						AdvisoryID: "ELSA-2017-3520",
						Severity:   "Important",
						Issued:     issued,
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
			sort.Strings(tt.out[i].CveIDs)
			sort.Strings(advisoryCveIDs.CveIDs)
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
	r.Distro = config.Distro{Family: "redhat"}

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

func TestParseYumCheckUpdateLines(t *testing.T) {
	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{Family: "centos"}
	stdout := `Loaded plugins: changelog, fastestmirror, keys, protect-packages, protectbase, security
Loading mirror speeds from cached hostfile
 * base: mirror.fairway.ne.jp
 * epel: epel.mirror.srv.co.ge
 * extras: mirror.fairway.ne.jp
 * updates: mirror.fairway.ne.jp
0 packages excluded due to repository protections

audit-libs.x86_64              2.3.7-5.el6                   base
bash.x86_64                    4.1.2-33.el6_7.1              updates
Obsoleting Packages
python-libs.i686    2.6.6-64.el6   rhui-REGION-rhel-server-releases
    python-ordereddict.noarch     1.1-3.el6ev    installed
bind-utils.x86_64                       30:9.3.6-25.P1.el5_11.8          updates
pytalloc.x86_64                 2.0.7-2.el6                      @CentOS 6.5/6.5
`

	r.setPackages(models.NewPackages(
		models.Package{
			Name:    "audit-libs",
			Version: "2.3.6",
			Release: "4.el6",
		},
		models.Package{
			Name:    "bash",
			Version: "4.1.1",
			Release: "33",
		},
		models.Package{
			Name:    "python-libs",
			Version: "2.6.0",
			Release: "1.1-0",
		},
		models.Package{
			Name:    "python-ordereddict",
			Version: "1.0",
			Release: "1",
		},
		models.Package{
			Name:    "bind-utils",
			Version: "1.0",
			Release: "1",
		},
		models.Package{
			Name:    "pytalloc",
			Version: "2.0.1",
			Release: "0",
		},
	))
	var tests = []struct {
		in  string
		out models.Packages
	}{
		{
			stdout,
			models.NewPackages(
				models.Package{
					Name:       "audit-libs",
					Version:    "2.3.6",
					Release:    "4.el6",
					NewVersion: "2.3.7",
					NewRelease: "5.el6",
					Repository: "base",
				},
				models.Package{
					Name:       "bash",
					Version:    "4.1.1",
					Release:    "33",
					NewVersion: "4.1.2",
					NewRelease: "33.el6_7.1",
					Repository: "updates",
				},
				models.Package{
					Name:       "python-libs",
					Version:    "2.6.0",
					Release:    "1.1-0",
					NewVersion: "2.6.6",
					NewRelease: "64.el6",
					Repository: "rhui-REGION-rhel-server-releases",
				},
				models.Package{
					Name:       "python-ordereddict",
					Version:    "1.0",
					Release:    "1",
					NewVersion: "1.1",
					NewRelease: "3.el6ev",
					Repository: "installed",
				},
				models.Package{
					Name:       "bind-utils",
					Version:    "1.0",
					Release:    "1",
					NewVersion: "30:9.3.6",
					NewRelease: "25.P1.el5_11.8",
					Repository: "updates",
				},
				models.Package{
					Name:       "pytalloc",
					Version:    "2.0.1",
					Release:    "0",
					NewVersion: "2.0.7",
					NewRelease: "2.el6",
					Repository: "@CentOS 6.5/6.5",
				},
			),
		},
	}

	for _, tt := range tests {
		packages, err := r.parseYumCheckUpdateLines(tt.in)
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
	stdout := `Loaded plugins: priorities, update-motd, upgrade-helper
34 package(s) needed for security, out of 71 available

bind-libs.x86_64           32:9.8.2-0.37.rc1.45.amzn1      amzn-main
java-1.7.0-openjdk.x86_64  1.7.0.95-2.6.4.0.65.amzn1     amzn-main
if-not-architecture        100-200                         amzn-main
`
	r.Packages = models.NewPackages(
		models.Package{
			Name:    "bind-libs",
			Version: "9.8.0",
			Release: "0.33.rc1.45.amzn1",
		},
		models.Package{
			Name:    "java-1.7.0-openjdk",
			Version: "1.7.0.0",
			Release: "2.6.4.0.0.amzn1",
		},
		models.Package{
			Name:    "if-not-architecture",
			Version: "10",
			Release: "20",
		},
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
					Version:    "9.8.0",
					Release:    "0.33.rc1.45.amzn1",
					NewVersion: "32:9.8.2",
					NewRelease: "0.37.rc1.45.amzn1",
					Repository: "amzn-main",
				},
				models.Package{
					Name:       "java-1.7.0-openjdk",
					Version:    "1.7.0.0",
					Release:    "2.6.4.0.0.amzn1",
					NewVersion: "1.7.0.95",
					NewRelease: "2.6.4.0.65.amzn1",
					Repository: "amzn-main",
				},
				models.Package{
					Name:       "if-not-architecture",
					Version:    "10",
					Release:    "20",
					NewVersion: "100",
					NewRelease: "200",
					Repository: "amzn-main",
				},
			),
		},
	}

	for _, tt := range tests {
		packages, err := r.parseYumCheckUpdateLines(tt.in)
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

const (
	/* for CentOS6,7 (yum-util >= 1.1.20) */
	stdoutCentos6 = `---> Package libaio.x86_64 0:0.3.107-10.el6 will be installed
--> Finished Dependency Resolution

Changes in packages about to be updated:

ChangeLog for: binutils-2.20.51.0.2-5.44.el6.x86_64
* Mon Dec  7 21:00:00 2015 Nick Clifton <nickc@redhat.com> - 2.20.51.0.2-5.44
- Backport upstream RELRO fixes. (#1227839)

** No ChangeLog for: chkconfig-1.3.49.5-1.el6.x86_64

ChangeLog for: coreutils-8.4-43.el6.x86_64, coreutils-libs-8.4-43.el6.x86_64
* Wed Feb 10 21:00:00 2016 Ondrej Vasik <ovasik@redhat.com> - 8.4-43
- sed should actually be /bin/sed (related #1222140)

* Wed Jan  6 21:00:00 2016 Ondrej Vasik <ovasik@redhat.com> - 8.4-41
- colorls.sh,colorls.csh - call utilities with complete path (#1222140)
- mkdir, mkfifo, mknod - respect default umask/acls when
  COREUTILS_CHILD_DEFAULT_ACLS envvar is set (to match rhel 7 behaviour,

ChangeLog for: centos-release-6-8.el6.centos.12.3.x86_64
* Wed May 18 21:00:00 2016 Johnny Hughes <johnny@centos.org> 6-8.el6.centos.12.3
- CentOS-6.8 Released
- TESTSTRING CVE-0000-0000

ChangeLog for: 12:dhclient-4.1.1-51.P1.el6.centos.x86_64, 12:dhcp-common-4.1.1-51.P1.el6.centos.x86_64
* Tue May 10 21:00:00 2016 Johnny Hughes <johnny@centos.org> - 12:4.1.1-51.P1
- created patch 1000 for CentOS Branding
- replaced vvendor variable with CentOS in the SPEC file
- TESTSTRING CVE-1111-1111

* Mon Jan 11 21:00:00 2016 Jiri Popelka <jpopelka@redhat.com> - 12:4.1.1-51.P1
- send unicast request/release via correct interface (#1297445)

* Thu Dec  3 21:00:00 2015 Jiri Popelka <jpopelka@redhat.com> - 12:4.1.1-50.P1
- Lease table overflow crash. (#1133917)
- Add ignore-client-uids option. (#1196768)
- dhclient-script: it's OK if the arping reply comes from our system. (#1204095)
- VLAN ID is only bottom 12-bits of TCI. (#1259552)
- dhclient: Make sure link-local address is ready in stateless mode. (#1263466)
- dhclient-script: make_resolv_conf(): Keep old nameservers
  if server sends domain-name/search, but no nameservers. (#1269595)

ChangeLog for: file-5.04-30.el6.x86_64, file-libs-5.04-30.el6.x86_64
* Tue Feb 16 21:00:00 2016 Jan Kaluza <jkaluza@redhat.com> 5.04-30
- fix CVE-2014-3538 (unrestricted regular expression matching)

* Tue Jan  5 21:00:00 2016 Jan Kaluza <jkaluza@redhat.com> 5.04-29
- fix #1284826 - try to read ELF header to detect corrupted one

* Wed Dec 16 21:00:00 2015 Jan Kaluza <jkaluza@redhat.com> 5.04-28
- fix #1263987 - fix bugs found by coverity in the patch

* Thu Nov 26 21:00:00 2015 Jan Kaluza <jkaluza@redhat.com> 5.04-27
- fix CVE-2014-3587 (incomplete fix for CVE-2012-1571)
- fix CVE-2014-3710 (out-of-bounds read in elf note headers)
- fix CVE-2014-8116 (multiple DoS issues (resource consumption))
- fix CVE-2014-8117 (denial of service issue (resource consumption))
- fix CVE-2014-9620 (limit the number of ELF notes processed)
- fix CVE-2014-9653 (malformed elf file causes access to uninitialized memory)


Dependencies Resolved

`
	/* for CentOS5 (yum-util < 1.1.20) */
	stdoutCentos5 = `---> Package portmap.i386 0:4.0-65.2.2.1 set to be updated
--> Finished Dependency Resolution

Changes in packages about to be updated:

libuser-0.54.7-3.el5.i386
nss_db-2.2-38.el5_11.i386
* Thu Nov 20 23:00:00 2014 Nalin Dahyabhai <nalin@redhat.com> - 2.2-38
- build without strict aliasing (internal build tooling)

* Sat Nov 15 23:00:00 2014 Nalin Dahyabhai <nalin@redhat.com> - 2.2-37
- pull in fix for a memory leak in nss_db (#1163493)

acpid-1.0.4-12.el5.i386
* Thu Oct  6 00:00:00 2011 Jiri Skala <jskala@redhat.com> - 1.0.4-12
- Resolves: #729769 - acpid dumping useless info to log

nash-5.1.19.6-82.el5.i386, mkinitrd-5.1.19.6-82.el5.i386
* Tue Apr 15 00:00:00 2014 Brian C. Lane <bcl@redhat.com> 5.1.19.6-82
- Use ! instead of / when searching sysfs for ccis device
  Resolves: rhbz#988020
- Always include ahci module (except on s390) (bcl)
  Resolves: rhbz#978245
- Prompt to recreate default initrd (karsten)
  Resolves: rhbz#472764

util-linux-2.13-0.59.el5_8.i386
* Wed Oct 17 00:00:00 2012 Karel Zak <kzak@redhat.com> 2.13-0.59.el5_8
- fix #865791 - fdisk fails to partition disk not in use

* Wed Dec 21 23:00:00 2011 Karel Zak <kzak@redhat.com> 2.13-0.59
- fix #768382 - CVE-2011-1675 CVE-2011-1677 util-linux various flaws

* Wed Oct 26 00:00:00 2011 Karel Zak <kzak@redhat.com> 2.13-0.58
- fix #677452 - util-linux fails to build with gettext-0.17

30:bind-utils-9.3.6-25.P1.el5_11.8.i386, 30:bind-libs-9.3.6-25.P1.el5_11.8.i386
* Mon Mar 14 23:00:00 2016 Tomas Hozza <thozza@redhat.com> - 30:9.3.6-25.P1.8
- Fix issue with patch for CVE-2016-1285 and CVE-2016-1286 found by test suite

* Wed Mar  9 23:00:00 2016 Tomas Hozza <thozza@redhat.com> - 30:9.3.6-25.P1.7
- Fix CVE-2016-1285 and CVE-2016-1286

* Mon Jan 18 23:00:00 2016 Tomas Hozza <thozza@redhat.com> - 30:9.3.6-25.P1.6
- Fix CVE-2015-8704

* Thu Sep  3 00:00:00 2015 Tomas Hozza <thozza@redhat.com> - 30:9.3.6-25.P1.5
- Fix CVE-2015-8000


Dependencies Resolved

`
)

func TestGetChangelogCVELines(t *testing.T) {
	var testsCentos6 = []struct {
		in  models.Package
		out string
	}{
		{
			models.Package{
				Name:       "binutils",
				NewVersion: "2.20.51.0.2",
				NewRelease: "5.44.el6",
			},
			"",
		},
		{
			models.Package{
				Name:       "centos-release",
				NewVersion: "6",
				NewRelease: "8.el6.centos.12.3",
			},
			`- TESTSTRING CVE-0000-0000
`,
		},
		{
			models.Package{
				Name:       "dhclient",
				NewVersion: "12:4.1.1",
				NewRelease: "51.P1.el6.centos",
			},
			`- TESTSTRING CVE-1111-1111
`,
		},
		{
			models.Package{
				Name:       "dhcp-common",
				NewVersion: "12:4.1.1",
				NewRelease: "51.P1.el6.centos",
			},
			`- TESTSTRING CVE-1111-1111
`,
		},
		{
			models.Package{
				Name:       "coreutils-libs",
				NewVersion: "8.4",
				NewRelease: "43.el6",
			},
			"",
		},
		{
			models.Package{
				Name:       "file",
				NewVersion: "5.04",
				NewRelease: "30.el6",
			},
			`- fix CVE-2014-3538 (unrestricted regular expression matching)
- fix CVE-2014-3587 (incomplete fix for CVE-2012-1571)
- fix CVE-2014-3710 (out-of-bounds read in elf note headers)
- fix CVE-2014-8116 (multiple DoS issues (resource consumption))
- fix CVE-2014-8117 (denial of service issue (resource consumption))
- fix CVE-2014-9620 (limit the number of ELF notes processed)
- fix CVE-2014-9653 (malformed elf file causes access to uninitialized memory)
`,
		},
		{
			models.Package{
				Name:       "file-libs",
				NewVersion: "5.04",
				NewRelease: "30.el6",
			},
			`- fix CVE-2014-3538 (unrestricted regular expression matching)
- fix CVE-2014-3587 (incomplete fix for CVE-2012-1571)
- fix CVE-2014-3710 (out-of-bounds read in elf note headers)
- fix CVE-2014-8116 (multiple DoS issues (resource consumption))
- fix CVE-2014-8117 (denial of service issue (resource consumption))
- fix CVE-2014-9620 (limit the number of ELF notes processed)
- fix CVE-2014-9653 (malformed elf file causes access to uninitialized memory)
`,
		},
	}

	r := newRedhat(config.ServerInfo{})
	r.Distro = config.Distro{
		Family:  "centos",
		Release: "6.7",
	}
	for _, tt := range testsCentos6 {
		rpm2changelog, err := r.divideChangelogByPackage(stdoutCentos6)
		if err != nil {
			t.Errorf("err: %s", err)
		}
		changelog := r.getChangelogCVELines(rpm2changelog, tt.in)
		if tt.out != changelog {
			t.Errorf("line: expected %s, actual %s, tt: %#v", tt.out, changelog, tt)
		}
	}

	var testsCentos5 = []struct {
		in  models.Package
		out string
	}{
		{
			models.Package{
				Name:       "libuser",
				NewVersion: "0.54.7",
				NewRelease: "3.el5",
			},
			"",
		},
		{
			models.Package{
				Name:       "nss_db",
				NewVersion: "2.2",
				NewRelease: "38.el5_11",
			},
			"",
		},
		{
			models.Package{
				Name:       "acpid",
				NewVersion: "1.0.4",
				NewRelease: "82.el5",
			},
			"",
		},
		{
			models.Package{
				Name:       "mkinitrd",
				NewVersion: "5.1.19.6",
				NewRelease: "82.el5",
			},
			"",
		},
		{
			models.Package{
				Name:       "util-linux",
				NewVersion: "2.13",
				NewRelease: "0.59.el5_8",
			},
			`- fix #768382 - CVE-2011-1675 CVE-2011-1677 util-linux various flaws
`,
		},
		{
			models.Package{
				Name:       "bind-libs",
				NewVersion: "30:9.3.6",
				NewRelease: "25.P1.el5_11.8",
			},
			`- Fix issue with patch for CVE-2016-1285 and CVE-2016-1286 found by test suite
- Fix CVE-2016-1285 and CVE-2016-1286
- Fix CVE-2015-8704
- Fix CVE-2015-8000
`,
		},
		{
			models.Package{
				Name:       "bind-utils",
				NewVersion: "30:9.3.6",
				NewRelease: "25.P1.el5_11.8",
			},
			`- Fix issue with patch for CVE-2016-1285 and CVE-2016-1286 found by test suite
- Fix CVE-2016-1285 and CVE-2016-1286
- Fix CVE-2015-8704
- Fix CVE-2015-8000
`,
		},
	}

	r.Distro = config.Distro{
		Family:  "centos",
		Release: "5.6",
	}
	for _, tt := range testsCentos5 {
		rpm2changelog, err := r.divideChangelogByPackage(stdoutCentos5)
		if err != nil {
			t.Errorf("err: %s", err)
		}
		changelog := r.getChangelogCVELines(rpm2changelog, tt.in)
		if tt.out != changelog {
			t.Errorf("line: expected %s, actual %s, tt: %#v", tt.out, changelog, tt)
		}
	}
}
