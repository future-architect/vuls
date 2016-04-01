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

	"github.com/future-architect/vuls/config"
	"github.com/k0kubun/pp"
)

func TestParseScanedPackagesLineDebian(t *testing.T) {

	var packagetests = []struct {
		in      string
		name    string
		version string
	}{
		{"base-passwd	3.5.33", "base-passwd", "3.5.33"},
		{"bzip2	1.0.6-5", "bzip2", "1.0.6-5"},
		{"adduser	3.113+nmu3ubuntu3", "adduser", "3.113+nmu3ubuntu3"},
		{"bash	4.3-7ubuntu1.5", "bash", "4.3-7ubuntu1.5"},
		{"bsdutils	1:2.20.1-5.1ubuntu20.4", "bsdutils", "1:2.20.1-5.1ubuntu20.4"},
		{"ca-certificates	20141019ubuntu0.14.04.1", "ca-certificates", "20141019ubuntu0.14.04.1"},
		{"apt	1.0.1ubuntu2.8", "apt", "1.0.1ubuntu2.8"},
	}

	d := newDebian(config.ServerInfo{})
	for _, tt := range packagetests {
		n, v, _ := d.parseScanedPackagesLine(tt.in)
		if n != tt.name {
			t.Errorf("name: expected %s, actual %s", tt.name, n)
		}
		if v != tt.version {
			t.Errorf("version: expected %s, actual %s", tt.version, v)
		}
	}

}

func TestgetCveIDParsingChangelog(t *testing.T) {

	var tests = []struct {
		in       []string
		expected []string
	}{
		{
			// verubuntu1
			[]string{
				"systemd",
				"228-4ubuntu1",
				`systemd (229-2) unstable; urgency=medium
systemd (229-1) unstable; urgency=medium
systemd (228-6) unstable; urgency=medium
CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
CVE-2015-3210: heap buffer overflow in pcre_compile2() /
systemd (228-5) unstable; urgency=medium
systemd (228-4) unstable; urgency=medium
systemd (228-3) unstable; urgency=medium
systemd (228-2) unstable; urgency=medium
systemd (228-1) unstable; urgency=medium
systemd (227-3) unstable; urgency=medium
systemd (227-2) unstable; urgency=medium
systemd (227-1) unstable; urgency=medium`,
			},
			[]string{
				"CVE-2015-2325",
				"CVE-2015-2326",
				"CVE-2015-3210",
			},
		},

		{
			// ver
			[]string{
				"libpcre3",
				"2:8.38-1ubuntu1",
				`pcre3 (2:8.38-2) unstable; urgency=low
pcre3 (2:8.38-1) unstable; urgency=low
pcre3 (2:8.35-8) unstable; urgency=low
pcre3 (2:8.35-7.4) unstable; urgency=medium
pcre3 (2:8.35-7.3) unstable; urgency=medium
pcre3 (2:8.35-7.2) unstable; urgency=low
CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
CVE-2015-3210: heap buffer overflow in pcre_compile2() /
pcre3 (2:8.35-7.1) unstable; urgency=medium
pcre3 (2:8.35-7) unstable; urgency=medium`,
			},
			[]string{
				"CVE-2015-2325",
				"CVE-2015-2326",
				"CVE-2015-3210",
			},
		},

		{
			// ver-ubuntu3
			[]string{
				"sysvinit",
				"2.88dsf-59.2ubuntu3",
				`sysvinit (2.88dsf-59.3ubuntu1) xenial; urgency=low
sysvinit (2.88dsf-59.3) unstable; urgency=medium
CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
CVE-2015-3210: heap buffer overflow in pcre_compile2() /
sysvinit (2.88dsf-59.2ubuntu3) xenial; urgency=medium
sysvinit (2.88dsf-59.2ubuntu2) wily; urgency=medium
sysvinit (2.88dsf-59.2ubuntu1) wily; urgency=medium
CVE-2015-2321: heap buffer overflow in pcre_compile2(). (Closes: #783285)
sysvinit (2.88dsf-59.2) unstable; urgency=medium
sysvinit (2.88dsf-59.1ubuntu3) wily; urgency=medium
CVE-2015-2322: heap buffer overflow in pcre_compile2(). (Closes: #783285)
sysvinit (2.88dsf-59.1ubuntu2) wily; urgency=medium
sysvinit (2.88dsf-59.1ubuntu1) wily; urgency=medium
sysvinit (2.88dsf-59.1) unstable; urgency=medium
CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
sysvinit (2.88dsf-59) unstable; urgency=medium
sysvinit (2.88dsf-58) unstable; urgency=low
sysvinit (2.88dsf-57) unstable; urgency=low`,
			},
			[]string{
				"CVE-2015-2325",
				"CVE-2015-2326",
				"CVE-2015-3210",
			},
		},
		{
			// 1:ver-ubuntu3
			[]string{
				"bsdutils",
				"1:2.27.1-1ubuntu3",
				` util-linux (2.27.1-3ubuntu1) xenial; urgency=medium
util-linux (2.27.1-3) unstable; urgency=medium
CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
CVE-2015-3210: heap buffer overflow in pcre_compile2() /
util-linux (2.27.1-2) unstable; urgency=medium
util-linux (2.27.1-1ubuntu4) xenial; urgency=medium
util-linux (2.27.1-1ubuntu3) xenial; urgency=medium
util-linux (2.27.1-1ubuntu2) xenial; urgency=medium
util-linux (2.27.1-1ubuntu1) xenial; urgency=medium
util-linux (2.27.1-1) unstable; urgency=medium
util-linux (2.27-3ubuntu1) xenial; urgency=medium
util-linux (2.27-3) unstable; urgency=medium
util-linux (2.27-2) unstable; urgency=medium
util-linux (2.27-1) unstable; urgency=medium
util-linux (2.27~rc2-2) experimental; urgency=medium
util-linux (2.27~rc2-1) experimental; urgency=medium
util-linux (2.27~rc1-1) experimental; urgency=medium
util-linux (2.26.2-9) unstable; urgency=medium
util-linux (2.26.2-8) experimental; urgency=medium
util-linux (2.26.2-7) experimental; urgency=medium
util-linux (2.26.2-6ubuntu3) wily; urgency=medium
CVE-2015-2329: heap buffer overflow in compile_branch(). (Closes: #781795)
util-linux (2.26.2-6ubuntu2) wily; urgency=medium
util-linux (2.26.2-6ubuntu1) wily; urgency=medium
util-linux (2.26.2-6) unstable; urgency=medium`,
			},
			[]string{
				"CVE-2015-2325",
				"CVE-2015-2326",
				"CVE-2015-3210",
			},
		},
	}

	d := newDebian(config.ServerInfo{})
	for _, tt := range tests {
		actual, _ := d.getCveIDParsingChangelog(tt.in[2], tt.in[0], tt.in[1])
		if len(actual) != len(tt.expected) {
			t.Errorf("Len of return array are'nt same. expected %#v, actual %#v", tt.expected, actual)
			continue
		}
		for i := range tt.expected {
			if actual[i] != tt.expected[i] {
				t.Errorf("expected %s, actual %s", tt.expected[i], actual[i])
			}
		}
	}

	for _, tt := range tests {
		_, err := d.getCveIDParsingChangelog(tt.in[2], tt.in[0], "version number do'nt match case")
		if err != nil {
			t.Errorf("Returning error is unexpected.")
		}
	}
}

func TestGetUpdatablePackNames(t *testing.T) {

	var tests = []struct {
		in       string
		expected []string
	}{
		{ // Ubuntu 12.04
			`Reading package lists... Done
Building dependency tree
Reading state information... Done
The following packages will be upgraded:
  apt ca-certificates cpio dpkg e2fslibs e2fsprogs gnupg gpgv libc-bin libc6 libcomerr2 libpcre3
  libpng12-0 libss2 libssl1.0.0 libudev0 multiarch-support openssl tzdata udev upstart
21 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst dpkg [1.16.1.2ubuntu7.5] (1.16.1.2ubuntu7.7 Ubuntu:12.04/precise-updates [amd64])
Conf dpkg (1.16.1.2ubuntu7.7 Ubuntu:12.04/precise-updates [amd64])
Inst upstart [1.5-0ubuntu7.2] (1.5-0ubuntu7.3 Ubuntu:12.04/precise-updates [amd64])
Inst libc-bin [2.15-0ubuntu10.10] (2.15-0ubuntu10.13 Ubuntu:12.04/precise-updates [amd64]) [libc6:amd64 ]
Conf libc-bin (2.15-0ubuntu10.13 Ubuntu:12.04/precise-updates [amd64]) [libc6:amd64 ]
Inst libc6 [2.15-0ubuntu10.10] (2.15-0ubuntu10.13 Ubuntu:12.04/precise-updates [amd64])
Conf libc6 (2.15-0ubuntu10.13 Ubuntu:12.04/precise-updates [amd64])
Inst libudev0 [175-0ubuntu9.9] (175-0ubuntu9.10 Ubuntu:12.04/precise-updates [amd64])
Inst tzdata [2015a-0ubuntu0.12.04] (2015g-0ubuntu0.12.04 Ubuntu:12.04/precise-updates [all])
Conf tzdata (2015g-0ubuntu0.12.04 Ubuntu:12.04/precise-updates [all])
Inst e2fslibs [1.42-1ubuntu2] (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64]) [e2fsprogs:amd64 on e2fslibs:amd64] [e2fsprogs:amd64 ]
Conf e2fslibs (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64]) [e2fsprogs:amd64 ]
Inst e2fsprogs [1.42-1ubuntu2] (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64])
Conf e2fsprogs (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64])
Inst gpgv [1.4.11-3ubuntu2.7] (1.4.11-3ubuntu2.9 Ubuntu:12.04/precise-updates [amd64])
Conf gpgv (1.4.11-3ubuntu2.9 Ubuntu:12.04/precise-updates [amd64])
Inst gnupg [1.4.11-3ubuntu2.7] (1.4.11-3ubuntu2.9 Ubuntu:12.04/precise-updates [amd64])
Conf gnupg (1.4.11-3ubuntu2.9 Ubuntu:12.04/precise-updates [amd64])
Inst apt [0.8.16~exp12ubuntu10.22] (0.8.16~exp12ubuntu10.26 Ubuntu:12.04/precise-updates [amd64])
Conf apt (0.8.16~exp12ubuntu10.26 Ubuntu:12.04/precise-updates [amd64])
Inst libcomerr2 [1.42-1ubuntu2] (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64])
Conf libcomerr2 (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64])
Inst libss2 [1.42-1ubuntu2] (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64])
Conf libss2 (1.42-1ubuntu2.3 Ubuntu:12.04/precise-updates [amd64])
Inst libssl1.0.0 [1.0.1-4ubuntu5.21] (1.0.1-4ubuntu5.34 Ubuntu:12.04/precise-updates [amd64])
Conf libssl1.0.0 (1.0.1-4ubuntu5.34 Ubuntu:12.04/precise-updates [amd64])
Inst libpcre3 [8.12-4] (8.12-4ubuntu0.1 Ubuntu:12.04/precise-updates [amd64])
Inst libpng12-0 [1.2.46-3ubuntu4] (1.2.46-3ubuntu4.2 Ubuntu:12.04/precise-updates [amd64])
Inst multiarch-support [2.15-0ubuntu10.10] (2.15-0ubuntu10.13 Ubuntu:12.04/precise-updates [amd64])
Conf multiarch-support (2.15-0ubuntu10.13 Ubuntu:12.04/precise-updates [amd64])
Inst cpio [2.11-7ubuntu3.1] (2.11-7ubuntu3.2 Ubuntu:12.04/precise-updates [amd64])
Inst udev [175-0ubuntu9.9] (175-0ubuntu9.10 Ubuntu:12.04/precise-updates [amd64])
Inst openssl [1.0.1-4ubuntu5.33] (1.0.1-4ubuntu5.34 Ubuntu:12.04/precise-updates [amd64])
Inst ca-certificates [20141019ubuntu0.12.04.1] (20160104ubuntu0.12.04.1 Ubuntu:12.04/precise-updates [all])
Conf libudev0 (175-0ubuntu9.10 Ubuntu:12.04/precise-updates [amd64])
Conf upstart (1.5-0ubuntu7.3 Ubuntu:12.04/precise-updates [amd64])
Conf libpcre3 (8.12-4ubuntu0.1 Ubuntu:12.04/precise-updates [amd64])
Conf libpng12-0 (1.2.46-3ubuntu4.2 Ubuntu:12.04/precise-updates [amd64])
Conf cpio (2.11-7ubuntu3.2 Ubuntu:12.04/precise-updates [amd64])
Conf udev (175-0ubuntu9.10 Ubuntu:12.04/precise-updates [amd64])
Conf openssl (1.0.1-4ubuntu5.34 Ubuntu:12.04/precise-updates [amd64])
Conf ca-certificates (20160104ubuntu0.12.04.1 Ubuntu:12.04/precise-updates [all])`,
			[]string{
				"apt",
				"ca-certificates",
				"cpio",
				"dpkg",
				"e2fslibs",
				"e2fsprogs",
				"gnupg",
				"gpgv",
				"libc-bin",
				"libc6",
				"libcomerr2",
				"libpcre3",
				"libpng12-0",
				"libss2",
				"libssl1.0.0",
				"libudev0",
				"multiarch-support",
				"openssl",
				"tzdata",
				"udev",
				"upstart",
			},
		},
		{ // Ubuntu 14.04
			`Reading package lists... Done
Building dependency tree
Reading state information... Done
Calculating upgrade... Done
The following packages will be upgraded:
  apt apt-utils base-files bsdutils coreutils cpio dh-python dpkg e2fslibs
  e2fsprogs gcc-4.8-base gcc-4.9-base gnupg gpgv ifupdown initscripts iproute2
  isc-dhcp-client isc-dhcp-common libapt-inst1.5 libapt-pkg4.12 libblkid1
  libc-bin libc6 libcgmanager0 libcomerr2 libdrm2 libexpat1 libffi6 libgcc1
  libgcrypt11 libgnutls-openssl27 libgnutls26 libmount1 libpcre3 libpng12-0
  libpython3.4-minimal libpython3.4-stdlib libsqlite3-0 libss2 libssl1.0.0
  libstdc++6 libtasn1-6 libudev1 libuuid1 login mount multiarch-support
  ntpdate passwd python3.4 python3.4-minimal rsyslog sudo sysv-rc
  sysvinit-utils tzdata udev util-linux
59 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst base-files [7.2ubuntu5.2] (7.2ubuntu5.4 Ubuntu:14.04/trusty-updates [amd64])
Conf base-files (7.2ubuntu5.4 Ubuntu:14.04/trusty-updates [amd64])
Inst coreutils [8.21-1ubuntu5.1] (8.21-1ubuntu5.3 Ubuntu:14.04/trusty-updates [amd64])
Conf coreutils (8.21-1ubuntu5.3 Ubuntu:14.04/trusty-updates [amd64])
Inst dpkg [1.17.5ubuntu5.3] (1.17.5ubuntu5.5 Ubuntu:14.04/trusty-updates [amd64])
Conf dpkg (1.17.5ubuntu5.5 Ubuntu:14.04/trusty-updates [amd64])
Inst libc-bin [2.19-0ubuntu6.5] (2.19-0ubuntu6.7 Ubuntu:14.04/trusty-updates [amd64])
Inst libc6 [2.19-0ubuntu6.5] (2.19-0ubuntu6.7 Ubuntu:14.04/trusty-updates [amd64])
Inst libgcc1 [1:4.9.1-0ubuntu1] (1:4.9.3-0ubuntu4 Ubuntu:14.04/trusty-updates [amd64]) []
Inst gcc-4.9-base [4.9.1-0ubuntu1] (4.9.3-0ubuntu4 Ubuntu:14.04/trusty-updates [amd64])
Conf gcc-4.9-base (4.9.3-0ubuntu4 Ubuntu:14.04/trusty-updates [amd64])
Conf libgcc1 (1:4.9.3-0ubuntu4 Ubuntu:14.04/trusty-updates [amd64])
Conf libc6 (2.19-0ubuntu6.7 Ubuntu:14.04/trusty-updates [amd64])
Conf libc-bin (2.19-0ubuntu6.7 Ubuntu:14.04/trusty-updates [amd64])
Inst e2fslibs [1.42.9-3ubuntu1] (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64]) [e2fsprogs:amd64 on e2fslibs:amd64] [e2fsprogs:amd64 ]
Conf e2fslibs (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64]) [e2fsprogs:amd64 ]
Inst e2fsprogs [1.42.9-3ubuntu1] (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64])
Conf e2fsprogs (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64])
Inst login [1:4.1.5.1-1ubuntu9] (1:4.1.5.1-1ubuntu9.2 Ubuntu:14.04/trusty-updates [amd64])
Conf login (1:4.1.5.1-1ubuntu9.2 Ubuntu:14.04/trusty-updates [amd64])
Inst mount [2.20.1-5.1ubuntu20.4] (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Conf mount (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Inst tzdata [2015a-0ubuntu0.14.04] (2015g-0ubuntu0.14.04 Ubuntu:14.04/trusty-updates [all])
Conf tzdata (2015g-0ubuntu0.14.04 Ubuntu:14.04/trusty-updates [all])
Inst sysvinit-utils [2.88dsf-41ubuntu6] (2.88dsf-41ubuntu6.3 Ubuntu:14.04/trusty-updates [amd64])
Inst sysv-rc [2.88dsf-41ubuntu6] (2.88dsf-41ubuntu6.3 Ubuntu:14.04/trusty-updates [all])
Conf sysv-rc (2.88dsf-41ubuntu6.3 Ubuntu:14.04/trusty-updates [all])
Conf sysvinit-utils (2.88dsf-41ubuntu6.3 Ubuntu:14.04/trusty-updates [amd64])
Inst util-linux [2.20.1-5.1ubuntu20.4] (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Conf util-linux (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Inst gcc-4.8-base [4.8.2-19ubuntu1] (4.8.4-2ubuntu1~14.04.1 Ubuntu:14.04/trusty-updates [amd64]) [libstdc++6:amd64 ]
Conf gcc-4.8-base (4.8.4-2ubuntu1~14.04.1 Ubuntu:14.04/trusty-updates [amd64]) [libstdc++6:amd64 ]
Inst libstdc++6 [4.8.2-19ubuntu1] (4.8.4-2ubuntu1~14.04.1 Ubuntu:14.04/trusty-updates [amd64])
Conf libstdc++6 (4.8.4-2ubuntu1~14.04.1 Ubuntu:14.04/trusty-updates [amd64])
Inst libapt-pkg4.12 [1.0.1ubuntu2.6] (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Conf libapt-pkg4.12 (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Inst gpgv [1.4.16-1ubuntu2.1] (1.4.16-1ubuntu2.3 Ubuntu:14.04/trusty-updates [amd64])
Conf gpgv (1.4.16-1ubuntu2.3 Ubuntu:14.04/trusty-updates [amd64])
Inst gnupg [1.4.16-1ubuntu2.1] (1.4.16-1ubuntu2.3 Ubuntu:14.04/trusty-updates [amd64])
Conf gnupg (1.4.16-1ubuntu2.3 Ubuntu:14.04/trusty-updates [amd64])
Inst apt [1.0.1ubuntu2.6] (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Conf apt (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Inst bsdutils [1:2.20.1-5.1ubuntu20.4] (1:2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Conf bsdutils (1:2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Inst passwd [1:4.1.5.1-1ubuntu9] (1:4.1.5.1-1ubuntu9.2 Ubuntu:14.04/trusty-updates [amd64])
Conf passwd (1:4.1.5.1-1ubuntu9.2 Ubuntu:14.04/trusty-updates [amd64])
Inst libuuid1 [2.20.1-5.1ubuntu20.4] (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Conf libuuid1 (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Inst libblkid1 [2.20.1-5.1ubuntu20.4] (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Conf libblkid1 (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Inst libcomerr2 [1.42.9-3ubuntu1] (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64])
Conf libcomerr2 (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64])
Inst libmount1 [2.20.1-5.1ubuntu20.4] (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Conf libmount1 (2.20.1-5.1ubuntu20.7 Ubuntu:14.04/trusty-updates [amd64])
Inst libpcre3 [1:8.31-2ubuntu2] (1:8.31-2ubuntu2.1 Ubuntu:14.04/trusty-updates [amd64])
Conf libpcre3 (1:8.31-2ubuntu2.1 Ubuntu:14.04/trusty-updates [amd64])
Inst libss2 [1.42.9-3ubuntu1] (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64])
Conf libss2 (1.42.9-3ubuntu1.3 Ubuntu:14.04/trusty-updates [amd64])
Inst libapt-inst1.5 [1.0.1ubuntu2.6] (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Inst libexpat1 [2.1.0-4ubuntu1] (2.1.0-4ubuntu1.1 Ubuntu:14.04/trusty-updates [amd64])
Inst libffi6 [3.1~rc1+r3.0.13-12] (3.1~rc1+r3.0.13-12ubuntu0.1 Ubuntu:14.04/trusty-updates [amd64])
Inst libgcrypt11 [1.5.3-2ubuntu4.1] (1.5.3-2ubuntu4.3 Ubuntu:14.04/trusty-updates [amd64])
Inst libtasn1-6 [3.4-3ubuntu0.1] (3.4-3ubuntu0.3 Ubuntu:14.04/trusty-updates [amd64])
Inst libgnutls-openssl27 [2.12.23-12ubuntu2.1] (2.12.23-12ubuntu2.4 Ubuntu:14.04/trusty-updates [amd64]) []
Inst libgnutls26 [2.12.23-12ubuntu2.1] (2.12.23-12ubuntu2.4 Ubuntu:14.04/trusty-updates [amd64])
Inst libsqlite3-0 [3.8.2-1ubuntu2] (3.8.2-1ubuntu2.1 Ubuntu:14.04/trusty-updates [amd64])
Inst python3.4 [3.4.0-2ubuntu1] (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64]) []
Inst libpython3.4-stdlib [3.4.0-2ubuntu1] (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64]) []
Inst python3.4-minimal [3.4.0-2ubuntu1] (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64]) []
Inst libssl1.0.0 [1.0.1f-1ubuntu2.8] (1.0.1f-1ubuntu2.16 Ubuntu:14.04/trusty-updates [amd64]) []
Inst libpython3.4-minimal [3.4.0-2ubuntu1] (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64])
Inst ntpdate [1:4.2.6.p5+dfsg-3ubuntu2.14.04.2] (1:4.2.6.p5+dfsg-3ubuntu2.14.04.8 Ubuntu:14.04/trusty-updates [amd64])
Inst libdrm2 [2.4.56-1~ubuntu2] (2.4.64-1~ubuntu14.04.1 Ubuntu:14.04/trusty-updates [amd64])
Inst libpng12-0 [1.2.50-1ubuntu2] (1.2.50-1ubuntu2.14.04.2 Ubuntu:14.04/trusty-updates [amd64])
Inst initscripts [2.88dsf-41ubuntu6] (2.88dsf-41ubuntu6.3 Ubuntu:14.04/trusty-updates [amd64])
Inst libcgmanager0 [0.24-0ubuntu7.3] (0.24-0ubuntu7.5 Ubuntu:14.04/trusty-updates [amd64])
Inst udev [204-5ubuntu20.10] (204-5ubuntu20.18 Ubuntu:14.04/trusty-updates [amd64]) []
Inst libudev1 [204-5ubuntu20.10] (204-5ubuntu20.18 Ubuntu:14.04/trusty-updates [amd64])
Inst multiarch-support [2.19-0ubuntu6.5] (2.19-0ubuntu6.7 Ubuntu:14.04/trusty-updates [amd64])
Conf multiarch-support (2.19-0ubuntu6.7 Ubuntu:14.04/trusty-updates [amd64])
Inst apt-utils [1.0.1ubuntu2.6] (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Inst dh-python [1.20140128-1ubuntu8] (1.20140128-1ubuntu8.2 Ubuntu:14.04/trusty-updates [all])
Inst iproute2 [3.12.0-2] (3.12.0-2ubuntu1 Ubuntu:14.04/trusty-updates [amd64])
Inst ifupdown [0.7.47.2ubuntu4.1] (0.7.47.2ubuntu4.3 Ubuntu:14.04/trusty-updates [amd64])
Inst isc-dhcp-client [4.2.4-7ubuntu12] (4.2.4-7ubuntu12.4 Ubuntu:14.04/trusty-updates [amd64]) []
Inst isc-dhcp-common [4.2.4-7ubuntu12] (4.2.4-7ubuntu12.4 Ubuntu:14.04/trusty-updates [amd64])
Inst rsyslog [7.4.4-1ubuntu2.5] (7.4.4-1ubuntu2.6 Ubuntu:14.04/trusty-updates [amd64])
Inst sudo [1.8.9p5-1ubuntu1] (1.8.9p5-1ubuntu1.2 Ubuntu:14.04/trusty-updates [amd64])
Inst cpio [2.11+dfsg-1ubuntu1.1] (2.11+dfsg-1ubuntu1.2 Ubuntu:14.04/trusty-updates [amd64])
Conf libapt-inst1.5 (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Conf libexpat1 (2.1.0-4ubuntu1.1 Ubuntu:14.04/trusty-updates [amd64])
Conf libffi6 (3.1~rc1+r3.0.13-12ubuntu0.1 Ubuntu:14.04/trusty-updates [amd64])
Conf libgcrypt11 (1.5.3-2ubuntu4.3 Ubuntu:14.04/trusty-updates [amd64])
Conf libtasn1-6 (3.4-3ubuntu0.3 Ubuntu:14.04/trusty-updates [amd64])
Conf libgnutls26 (2.12.23-12ubuntu2.4 Ubuntu:14.04/trusty-updates [amd64])
Conf libgnutls-openssl27 (2.12.23-12ubuntu2.4 Ubuntu:14.04/trusty-updates [amd64])
Conf libsqlite3-0 (3.8.2-1ubuntu2.1 Ubuntu:14.04/trusty-updates [amd64])
Conf libssl1.0.0 (1.0.1f-1ubuntu2.16 Ubuntu:14.04/trusty-updates [amd64])
Conf libpython3.4-minimal (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64])
Conf python3.4-minimal (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64])
Conf libpython3.4-stdlib (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64])
Conf python3.4 (3.4.3-1ubuntu1~14.04.3 Ubuntu:14.04/trusty-updates [amd64])
Conf ntpdate (1:4.2.6.p5+dfsg-3ubuntu2.14.04.8 Ubuntu:14.04/trusty-updates [amd64])
Conf libdrm2 (2.4.64-1~ubuntu14.04.1 Ubuntu:14.04/trusty-updates [amd64])
Conf libpng12-0 (1.2.50-1ubuntu2.14.04.2 Ubuntu:14.04/trusty-updates [amd64])
Conf initscripts (2.88dsf-41ubuntu6.3 Ubuntu:14.04/trusty-updates [amd64])
Conf libcgmanager0 (0.24-0ubuntu7.5 Ubuntu:14.04/trusty-updates [amd64])
Conf libudev1 (204-5ubuntu20.18 Ubuntu:14.04/trusty-updates [amd64])
Conf udev (204-5ubuntu20.18 Ubuntu:14.04/trusty-updates [amd64])
Conf apt-utils (1.0.1ubuntu2.11 Ubuntu:14.04/trusty-updates [amd64])
Conf dh-python (1.20140128-1ubuntu8.2 Ubuntu:14.04/trusty-updates [all])
Conf iproute2 (3.12.0-2ubuntu1 Ubuntu:14.04/trusty-updates [amd64])
Conf ifupdown (0.7.47.2ubuntu4.3 Ubuntu:14.04/trusty-updates [amd64])
Conf isc-dhcp-common (4.2.4-7ubuntu12.4 Ubuntu:14.04/trusty-updates [amd64])
Conf isc-dhcp-client (4.2.4-7ubuntu12.4 Ubuntu:14.04/trusty-updates [amd64])
Conf rsyslog (7.4.4-1ubuntu2.6 Ubuntu:14.04/trusty-updates [amd64])
Conf sudo (1.8.9p5-1ubuntu1.2 Ubuntu:14.04/trusty-updates [amd64])
Conf cpio (2.11+dfsg-1ubuntu1.2 Ubuntu:14.04/trusty-updates [amd64])
`,
			[]string{
				"apt",
				"apt-utils",
				"base-files",
				"bsdutils",
				"coreutils",
				"cpio",
				"dh-python",
				"dpkg",
				"e2fslibs",
				"e2fsprogs",
				"gcc-4.8-base",
				"gcc-4.9-base",
				"gnupg",
				"gpgv",
				"ifupdown",
				"initscripts",
				"iproute2",
				"isc-dhcp-client",
				"isc-dhcp-common",
				"libapt-inst1.5",
				"libapt-pkg4.12",
				"libblkid1",
				"libc-bin",
				"libc6",
				"libcgmanager0",
				"libcomerr2",
				"libdrm2",
				"libexpat1",
				"libffi6",
				"libgcc1",
				"libgcrypt11",
				"libgnutls-openssl27",
				"libgnutls26",
				"libmount1",
				"libpcre3",
				"libpng12-0",
				"libpython3.4-minimal",
				"libpython3.4-stdlib",
				"libsqlite3-0",
				"libss2",
				"libssl1.0.0",
				"libstdc++6",
				"libtasn1-6",
				"libudev1",
				"libuuid1",
				"login",
				"mount",
				"multiarch-support",
				"ntpdate",
				"passwd",
				"python3.4",
				"python3.4-minimal",
				"rsyslog",
				"sudo",
				"sysv-rc",
				"sysvinit-utils",
				"tzdata",
				"udev",
				"util-linux",
			},
		},
		{
			//Ubuntu12.04
			`Reading package lists... Done
Building dependency tree
Reading state information... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.`,
			[]string{},
		},
		{
			//Ubuntu14.04
			`Reading package lists... Done
Building dependency tree
Reading state information... Done
Calculating upgrade... Done
0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.`,
			[]string{},
		},
	}

	d := newDebian(config.ServerInfo{})
	for _, tt := range tests {
		actual, err := d.parseAptGetUpgrade(tt.in)
		if err != nil {
			t.Errorf("Returning error is unexpected.")
		}
		if len(tt.expected) != len(actual) {
			t.Errorf("Result length is not as same as expected. expected: %d, actual: %d", len(tt.expected), len(actual))
			pp.Println(tt.expected)
			pp.Println(actual)
			return
		}
		for i := range tt.expected {
			if tt.expected[i] != actual[i] {
				t.Errorf("[%d] expected %s, actual %s", i, tt.expected[i], actual[i])
			}
		}
	}
}

func TestParseAptCachePolicy(t *testing.T) {

	var tests = []struct {
		stdout   string
		name     string
		expected packCandidateVer
	}{
		{
			// Ubuntu 16.04
			`openssl:
  Installed: 1.0.2f-2ubuntu1
  Candidate: 1.0.2g-1ubuntu2
  Version table:
     1.0.2g-1ubuntu2 500
        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages
 *** 1.0.2f-2ubuntu1 100
        100 /var/lib/dpkg/status`,
			"openssl",
			packCandidateVer{
				Name:      "openssl",
				Installed: "1.0.2f-2ubuntu1",
				Candidate: "1.0.2g-1ubuntu2",
			},
		},
		{
			// Ubuntu 14.04
			`openssl:
  Installed: 1.0.1f-1ubuntu2.16
  Candidate: 1.0.1f-1ubuntu2.17
  Version table:
     1.0.1f-1ubuntu2.17 0
        500 http://archive.ubuntu.com/ubuntu/ trusty-updates/main amd64 Packages
        500 http://archive.ubuntu.com/ubuntu/ trusty-security/main amd64 Packages
 *** 1.0.1f-1ubuntu2.16 0
        100 /var/lib/dpkg/status
     1.0.1f-1ubuntu2 0
        500 http://archive.ubuntu.com/ubuntu/ trusty/main amd64 Packages`,
			"openssl",
			packCandidateVer{
				Name:      "openssl",
				Installed: "1.0.1f-1ubuntu2.16",
				Candidate: "1.0.1f-1ubuntu2.17",
			},
		},
		{
			// Ubuntu 12.04
			`openssl:
  Installed: 1.0.1-4ubuntu5.33
  Candidate: 1.0.1-4ubuntu5.34
  Version table:
     1.0.1-4ubuntu5.34 0
        500 http://archive.ubuntu.com/ubuntu/ precise-updates/main amd64 Packages
        500 http://archive.ubuntu.com/ubuntu/ precise-security/main amd64 Packages
 *** 1.0.1-4ubuntu5.33 0
        100 /var/lib/dpkg/status
     1.0.1-4ubuntu3 0
        500 http://archive.ubuntu.com/ubuntu/ precise/main amd64 Packages`,
			"openssl",
			packCandidateVer{
				Name:      "openssl",
				Installed: "1.0.1-4ubuntu5.33",
				Candidate: "1.0.1-4ubuntu5.34",
			},
		},
	}

	d := newDebian(config.ServerInfo{})
	for _, tt := range tests {
		actual, err := d.parseAptCachePolicy(tt.stdout, tt.name)
		if err != nil {
			t.Errorf("Error has occurred: %s, actual: %#v", err, actual)
		}
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("expected %s, actual %s", e, a)
		}
	}
}
