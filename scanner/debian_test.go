package scanner

import (
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/cache"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

func TestGetCveIDsFromChangelog(t *testing.T) {

	var tests = []struct {
		in        []string
		cveIDs    []DetectedCveID
		changelog models.Changelog
	}{
		{
			//0 verubuntu1
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
systemd (228-3) unstable; urgency=medium`,
			},
			[]DetectedCveID{
				{"CVE-2015-2325", models.ChangelogExactMatch},
				{"CVE-2015-2326", models.ChangelogExactMatch},
				{"CVE-2015-3210", models.ChangelogExactMatch},
			},
			models.Changelog{
				Contents: `systemd (229-2) unstable; urgency=medium
systemd (229-1) unstable; urgency=medium
systemd (228-6) unstable; urgency=medium
CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
CVE-2015-3210: heap buffer overflow in pcre_compile2() /
systemd (228-5) unstable; urgency=medium`,
				Method: models.ChangelogExactMatchStr,
			},
		},
		{
			//1 ver
			[]string{
				"libpcre3",
				"2:8.35-7.1ubuntu1",
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
			[]DetectedCveID{
				{"CVE-2015-2325", models.ChangelogExactMatch},
				{"CVE-2015-2326", models.ChangelogExactMatch},
				{"CVE-2015-3210", models.ChangelogExactMatch},
			},
			models.Changelog{
				Contents: `pcre3 (2:8.38-2) unstable; urgency=low
		 pcre3 (2:8.38-1) unstable; urgency=low
		 pcre3 (2:8.35-8) unstable; urgency=low
		 pcre3 (2:8.35-7.4) unstable; urgency=medium
		 pcre3 (2:8.35-7.3) unstable; urgency=medium
		 pcre3 (2:8.35-7.2) unstable; urgency=low
		 CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
		 CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
		 CVE-2015-3210: heap buffer overflow in pcre_compile2() /`,
				Method: models.ChangelogExactMatchStr,
			},
		},
		{
			//2 ver-ubuntu3
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
			[]DetectedCveID{
				{"CVE-2015-2325", models.ChangelogExactMatch},
				{"CVE-2015-2326", models.ChangelogExactMatch},
				{"CVE-2015-3210", models.ChangelogExactMatch},
			},
			models.Changelog{
				Contents: `sysvinit (2.88dsf-59.3ubuntu1) xenial; urgency=low
		 sysvinit (2.88dsf-59.3) unstable; urgency=medium
		 CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
		 CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
		 CVE-2015-3210: heap buffer overflow in pcre_compile2() /`,
				Method: models.ChangelogExactMatchStr,
			},
		},
		{
			//3  1:ver-ubuntu3
			[]string{
				"bsdutils",
				"1:2.27.1-1ubuntu3",
				`util-linux (2.27.1-3ubuntu1) xenial; urgency=medium
		 util-linux (2.27.1-3) unstable; urgency=medium
		 CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
		 CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
		 CVE-2015-3210: CVE-2016-1000000heap buffer overflow in pcre_compile2() /
		 util-linux (2.27.1-2) unstable; urgency=medium
		 util-linux (2.27.1-1ubuntu4) xenial; urgency=medium
		 util-linux (2.27.1-1ubuntu3) xenial; urgency=medium
		 util-linux (2.27.1-1ubuntu2) xenial; urgency=medium
		 util-linux (2.27.1-1ubuntu1) xenial; urgency=medium
		 util-linux (2.27.1-1) unstable; urgency=medium
		 util-linux (2.27-3ubuntu1) xenial; urgency=medium`,
			},
			[]DetectedCveID{
				// {"CVE-2015-2325", models.ChangelogLenientMatch},
				// {"CVE-2015-2326", models.ChangelogLenientMatch},
				// {"CVE-2015-3210", models.ChangelogLenientMatch},
				// {"CVE-2016-1000000", models.ChangelogLenientMatch},
			},
			models.Changelog{
				// Contents: `util-linux (2.27.1-3ubuntu1) xenial; urgency=medium
				// util-linux (2.27.1-3) unstable; urgency=medium
				// CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
				// CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
				// CVE-2015-3210: CVE-2016-1000000heap buffer overflow in pcre_compile2() /
				// util-linux (2.27.1-2) unstable; urgency=medium
				// util-linux (2.27.1-1ubuntu4) xenial; urgency=medium
				// util-linux (2.27.1-1ubuntu3) xenial; urgency=medium`,
				Method: models.ChangelogExactMatchStr,
			},
		},
		{
			//4 1:ver-ubuntu3
			[]string{
				"bsdutils",
				"1:2.27-3ubuntu3",
				`util-linux (2.27.1-3ubuntu1) xenial; urgency=medium
		 util-linux (2.27.1-3) unstable; urgency=medium
		 CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
		 CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
		 CVE-2015-3210: CVE-2016-1000000heap buffer overflow in pcre_compile2() /
		 util-linux (2.27.1-2) unstable; urgency=medium
		 util-linux (2.27.1-1ubuntu4) xenial; urgency=medium
		 util-linux (2.27.1-1ubuntu3) xenial; urgency=medium
		 util-linux (2.27.1-1ubuntu2) xenial; urgency=medium
		 util-linux (2.27.1-1ubuntu1) xenial; urgency=medium
		 util-linux (2.27.1-1) unstable; urgency=medium
		 util-linux (2.27-3) xenial; urgency=medium`,
			},
			[]DetectedCveID{
				// {"CVE-2015-2325", models.ChangelogLenientMatch},
				// {"CVE-2015-2326", models.ChangelogLenientMatch},
				// {"CVE-2015-3210", models.ChangelogLenientMatch},
				// {"CVE-2016-1000000", models.ChangelogLenientMatch},
			},
			models.Changelog{
				// Contents: `util-linux (2.27.1-3ubuntu1) xenial; urgency=medium
				// util-linux (2.27.1-3) unstable; urgency=medium
				// CVE-2015-2325: heap buffer overflow in compile_branch(). (Closes: #781795)
				// CVE-2015-2326: heap buffer overflow in pcre_compile2(). (Closes: #783285)
				// CVE-2015-3210: CVE-2016-1000000heap buffer overflow in pcre_compile2() /
				// util-linux (2.27.1-2) unstable; urgency=medium
				// util-linux (2.27.1-1ubuntu4) xenial; urgency=medium
				// util-linux (2.27.1-1ubuntu3) xenial; urgency=medium
				// util-linux (2.27.1-1ubuntu2) xenial; urgency=medium
				// util-linux (2.27.1-1ubuntu1) xenial; urgency=medium
				// util-linux (2.27.1-1) unstable; urgency=medium`,
				Method: models.ChangelogExactMatchStr,
			},
		},
		{
			//5 https://github.com/future-architect/vuls/pull/350
			[]string{
				"tar",
				"1.27.1-2+b1",
				`tar (1.27.1-2+deb8u1) jessie-security; urgency=high
		   * CVE-2016-6321: Bypassing the extract path name.
		 tar (1.27.1-2) unstable; urgency=low`,
			},
			[]DetectedCveID{
				{"CVE-2016-6321", models.ChangelogExactMatch},
			},
			models.Changelog{
				Contents: `tar (1.27.1-2+deb8u1) jessie-security; urgency=high
		   * CVE-2016-6321: Bypassing the extract path name.`,
				Method: models.ChangelogExactMatchStr,
			},
		},
	}

	d := newDebian(config.ServerInfo{})
	d.Distro.Family = "ubuntu"
	for i, tt := range tests {
		aCveIDs, aPack := d.getCveIDsFromChangelog(tt.in[2], tt.in[0], tt.in[1])
		if len(aCveIDs) != len(tt.cveIDs) {
			t.Errorf("[%d] Len of return array aren't same. expected %#v, actual %#v", i, tt.cveIDs, aCveIDs)
			t.Errorf(pp.Sprintf("%s", tt.in))
			continue
		}
		for j := range tt.cveIDs {
			if !reflect.DeepEqual(tt.cveIDs[j], aCveIDs[j]) {
				t.Errorf("[%d] expected %v, actual %v", i, tt.cveIDs[j], aCveIDs[j])
			}
		}

		if aPack.Changelog.Contents != tt.changelog.Contents {
			t.Error(pp.Sprintf("[%d] expected: %s, actual: %s", i, tt.changelog.Contents, aPack.Changelog.Contents))
		}

		if aPack.Changelog.Method != tt.changelog.Method {
			t.Error(pp.Sprintf("[%d] expected: %s, actual: %s", i, tt.changelog.Method, aPack.Changelog.Method))
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
21 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.`,
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
			t.Errorf("Returning error is unexpected")
		}
		if len(tt.expected) != len(actual) {
			t.Errorf("Result length is not as same as expected. expected: %d, actual: %d", len(tt.expected), len(actual))
			_, _ = pp.Println(tt.expected)
			_, _ = pp.Println(actual)
			return
		}
		for i := range tt.expected {
			if tt.expected[i] != actual[i] {
				t.Errorf("[%d] expected %s, actual %s", i, tt.expected[i], actual[i])
			}
		}
	}
}

func TestGetChangelogCache(t *testing.T) {
	const servername = "server1"
	pack := models.Package{
		Name:       "apt",
		Version:    "1.0.0",
		NewVersion: "1.0.1",
	}
	var meta = cache.Meta{
		Name: servername,
		Distro: config.Distro{
			Family:  "ubuntu",
			Release: "16.04",
		},
		Packs: models.Packages{
			"apt": pack,
		},
	}

	const path = "/tmp/vuls-test-cache-11111111.db"
	log := logging.NewNormalLogger()
	if err := cache.SetupBolt(path, log); err != nil {
		t.Errorf("Failed to setup bolt: %s", err)
	}
	defer os.Remove(path)

	if err := cache.DB.EnsureBuckets(meta); err != nil {
		t.Errorf("Failed to ensure buckets: %s", err)
	}

	d := newDebian(config.ServerInfo{})
	actual := d.getChangelogCache(&meta, pack)
	if actual != "" {
		t.Errorf("Failed to get empty string from cache:")
	}

	clog := "changelog-text"
	if err := cache.DB.PutChangelog(servername, "apt", clog); err != nil {
		t.Errorf("Failed to put changelog: %s", err)
	}

	actual = d.getChangelogCache(&meta, pack)
	if actual != clog {
		t.Errorf("Failed to get changelog from cache: %s", actual)
	}

	// increment a version of the pack
	pack.NewVersion = "1.0.2"
	actual = d.getChangelogCache(&meta, pack)
	if actual != "" {
		t.Errorf("The changelog is not invalidated: %s", actual)
	}

	// change a name of the pack
	pack.Name = "bash"
	actual = d.getChangelogCache(&meta, pack)
	if actual != "" {
		t.Errorf("The changelog is not invalidated: %s", actual)
	}
}

func TestSplitAptCachePolicy(t *testing.T) {
	var tests = []struct {
		stdout   string
		expected map[string]string
	}{
		// This function parse apt-cache policy by using Regexp multi-line mode.
		// So, test data includes "\r\n"
		{
			"apt:\r\n  Installed: 1.2.6\r\n  Candidate: 1.2.12~ubuntu16.04.1\r\n  Version table:\r\n     1.2.12~ubuntu16.04.1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages\r\n     1.2.10ubuntu1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages\r\n *** 1.2.6 100\r\n        100 /var/lib/dpkg/status\r\napt-utils:\r\n  Installed: 1.2.6\r\n  Candidate: 1.2.12~ubuntu16.04.1\r\n  Version table:\r\n     1.2.12~ubuntu16.04.1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages\r\n     1.2.10ubuntu1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages\r\n *** 1.2.6 100\r\n        100 /var/lib/dpkg/status\r\nbase-files:\r\n  Installed: 9.4ubuntu3\r\n  Candidate: 9.4ubuntu4.2\r\n  Version table:\r\n     9.4ubuntu4.2 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages\r\n     9.4ubuntu4 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages\r\n *** 9.4ubuntu3 100\r\n        100 /var/lib/dpkg/status\r\n",

			map[string]string{
				"apt": "apt:\r\n  Installed: 1.2.6\r\n  Candidate: 1.2.12~ubuntu16.04.1\r\n  Version table:\r\n     1.2.12~ubuntu16.04.1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages\r\n     1.2.10ubuntu1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages\r\n *** 1.2.6 100\r\n        100 /var/lib/dpkg/status\r\n",

				"apt-utils": "apt-utils:\r\n  Installed: 1.2.6\r\n  Candidate: 1.2.12~ubuntu16.04.1\r\n  Version table:\r\n     1.2.12~ubuntu16.04.1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages\r\n     1.2.10ubuntu1 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages\r\n *** 1.2.6 100\r\n        100 /var/lib/dpkg/status\r\n",

				"base-files": "base-files:\r\n  Installed: 9.4ubuntu3\r\n  Candidate: 9.4ubuntu4.2\r\n  Version table:\r\n     9.4ubuntu4.2 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial-updates/main amd64 Packages\r\n     9.4ubuntu4 500\r\n        500 http://archive.ubuntu.com/ubuntu xenial/main amd64 Packages\r\n *** 9.4ubuntu3 100\r\n        100 /var/lib/dpkg/status\r\n",
			},
		},
	}

	d := newDebian(config.ServerInfo{})
	for _, tt := range tests {
		actual := d.splitAptCachePolicy(tt.stdout)
		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("expected %s, actual %s", e, a)
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
				Repo:      "xenial/main",
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
				Repo:      "trusty-updates/main",
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
				Repo:      "precise-updates/main",
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

func TestParseCheckRestart(t *testing.T) {
	r := newDebian(config.ServerInfo{})
	r.Distro = config.Distro{Family: "debian"}
	var tests = []struct {
		in              string
		out             models.Packages
		unknownServices []string
	}{
		{
			in: `Found 27 processes using old versions of upgraded files
(19 distinct programs)
(15 distinct packages)

Of these, 14 seem to contain systemd service definitions or init scripts which can be used to restart them.
The following packages seem to have definitions that could be used
to restart their services:
varnish:
	3490	/usr/sbin/varnishd
	3704	/usr/sbin/varnishd
memcached:
	3636	/usr/bin/memcached
openssh-server:
	1252	/usr/sbin/sshd
	1184	/usr/sbin/sshd
accountsservice:
	462     /usr/lib/accountsservice/accounts-daemon

These are the systemd services:
systemctl restart accounts-daemon.service

These are the initd scripts:
service varnish restart
service memcached restart
service ssh restart

These processes (1) do not seem to have an associated init script to restart them:
util-linux:
	3650	/sbin/agetty
	3648	/sbin/agetty`,
			out: models.NewPackages(
				models.Package{
					Name: "varnish",
					NeedRestartProcs: []models.NeedRestartProcess{
						{
							PID:         "3490",
							Path:        "/usr/sbin/varnishd",
							ServiceName: "varnish",
							HasInit:     true,
						},
						{
							PID:         "3704",
							Path:        "/usr/sbin/varnishd",
							ServiceName: "varnish",
							HasInit:     true,
						},
					},
				},
				models.Package{
					Name: "memcached",
					NeedRestartProcs: []models.NeedRestartProcess{
						{
							PID:         "3636",
							Path:        "/usr/bin/memcached",
							ServiceName: "memcached",
							HasInit:     true,
						},
					},
				},
				models.Package{
					Name: "openssh-server",
					NeedRestartProcs: []models.NeedRestartProcess{
						{
							PID:         "1252",
							Path:        "/usr/sbin/sshd",
							ServiceName: "",
							HasInit:     true,
						},
						{
							PID:         "1184",
							Path:        "/usr/sbin/sshd",
							ServiceName: "",
							HasInit:     true,
						},
					},
				},
				models.Package{
					Name: "accountsservice",
					NeedRestartProcs: []models.NeedRestartProcess{
						{
							PID:         "462",
							Path:        "/usr/lib/accountsservice/accounts-daemon",
							ServiceName: "",
							HasInit:     true,
						},
					},
				},
				models.Package{
					Name: "util-linux",
					NeedRestartProcs: []models.NeedRestartProcess{
						{
							PID:     "3650",
							Path:    "/sbin/agetty",
							HasInit: false,
						},
						{
							PID:     "3648",
							Path:    "/sbin/agetty",
							HasInit: false,
						},
					},
				},
			),
			unknownServices: []string{"ssh"},
		},
		{
			in:              `Found 0 processes using old versions of upgraded files`,
			out:             models.Packages{},
			unknownServices: []string{},
		},
	}

	for _, tt := range tests {
		packages, services := r.parseCheckRestart(tt.in)
		for name, ePack := range tt.out {
			if !reflect.DeepEqual(ePack, packages[name]) {
				e := pp.Sprintf("%v", ePack)
				a := pp.Sprintf("%v", packages[name])
				t.Errorf("expected %s, actual %s", e, a)
			}
		}
		if !reflect.DeepEqual(tt.unknownServices, services) {
			t.Errorf("expected %s, actual %s", tt.unknownServices, services)
		}
	}
}

func Test_debian_parseGetPkgName(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name         string
		args         args
		wantPkgNames []string
	}{
		{
			name: "success",
			args: args{
				stdout: `udev: /lib/systemd/systemd-udevd
dpkg-query: no path found matching pattern /lib/modules/3.16.0-6-amd64/modules.alias.bin
udev: /lib/systemd/systemd-udevd
dpkg-query: no path found matching pattern /lib/udev/hwdb.bin
libuuid1:amd64: /lib/x86_64-linux-gnu/libuuid.so.1.3.0`,
			},
			wantPkgNames: []string{
				"libuuid1",
				"udev",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &debian{}
			gotPkgNames := o.parseGetPkgName(tt.args.stdout)
			sort.Strings(gotPkgNames)
			if !reflect.DeepEqual(gotPkgNames, tt.wantPkgNames) {
				t.Errorf("debian.parseGetPkgName() = %v, want %v", gotPkgNames, tt.wantPkgNames)
			}
		})
	}
}

func TestParseChangelog(t *testing.T) {
	type args struct {
		changelog string
		name      string
		ver       string
	}
	type expect struct {
		cveIDs []DetectedCveID
		pack   models.Package
	}
	tests := []struct {
		packName string
		args     args
		expect   expect
	}{
		{
			packName: "vlc",
			args: args{
				changelog: `vlc (3.0.11-0+deb10u1+rpt2) buster; urgency=medium

  * Add MMAL patch 19

 -- Serge Schneider <serge@raspberrypi.com>  Wed, 29 Jul 2020 14:28:28 +0100

vlc (3.0.11-0+deb10u1+rpt1) buster; urgency=high

  * Add MMAL patch 18
  * Add libxrandr-dev dependency
  * Add libdrm-dev dependency
  * Disable vdpau, libva, aom
  * Enable dav1d

 -- Serge Schneider <serge@raspberrypi.com>  Wed, 17 Jun 2020 10:30:58 +0100

vlc (3.0.11-0+deb10u1) buster-security; urgency=high

  * New upstream release
    - Fix heap-based buffer overflow in hxxx_nall (CVE-2020-13428)

 -- Sebastian Ramacher <sramacher@debian.org>  Mon, 15 Jun 2020 23:08:37 +0200

vlc (3.0.10-0+deb10u1) buster-security; urgency=medium`,
				name: "vlc",
				ver:  "3.0.10-0+deb10u1+rpt2",
			},
			expect: expect{
				cveIDs: []DetectedCveID{{"CVE-2020-13428", models.ChangelogExactMatch}},
				pack: models.Package{Changelog: &models.Changelog{
					Contents: `vlc (3.0.11-0+deb10u1+rpt2) buster; urgency=medium

  * Add MMAL patch 19

 -- Serge Schneider <serge@raspberrypi.com>  Wed, 29 Jul 2020 14:28:28 +0100

vlc (3.0.11-0+deb10u1+rpt1) buster; urgency=high

  * Add MMAL patch 18
  * Add libxrandr-dev dependency
  * Add libdrm-dev dependency
  * Disable vdpau, libva, aom
  * Enable dav1d

 -- Serge Schneider <serge@raspberrypi.com>  Wed, 17 Jun 2020 10:30:58 +0100

vlc (3.0.11-0+deb10u1) buster-security; urgency=high

  * New upstream release
    - Fix heap-based buffer overflow in hxxx_nall (CVE-2020-13428)

 -- Sebastian Ramacher <sramacher@debian.org>  Mon, 15 Jun 2020 23:08:37 +0200
`,
					Method: models.ChangelogExactMatchStr,
				}},
			},
		},
		{
			packName: "realvnc-vnc-server",
			args: args{
				changelog: `realvnc-vnc (6.7.2.42622) stable; urgency=low

  * Debian package for VNC Server

 -- RealVNC <noreply@realvnc.com>  Wed, 13 May 2020 19:51:40 +0100

`,
				name: "realvnc-vnc-server",
				ver:  "6.7.1.42348",
			},
			expect: expect{
				cveIDs: []DetectedCveID{},
				pack: models.Package{Changelog: &models.Changelog{
					Contents: `realvnc-vnc (6.7.2.42622) stable; urgency=low

  * Debian package for VNC Server

 -- RealVNC <noreply@realvnc.com>  Wed, 13 May 2020 19:51:40 +0100
`,
					Method: models.ChangelogLenientMatchStr,
				}},
			},
		},
	}

	o := newDebian(config.ServerInfo{})
	o.Distro = config.Distro{Family: constant.Raspbian}
	for _, tt := range tests {
		t.Run(tt.packName, func(t *testing.T) {
			cveIDs, pack, _ := o.parseChangelog(tt.args.changelog, tt.args.name, tt.args.ver, models.ChangelogExactMatch)
			if !reflect.DeepEqual(cveIDs, tt.expect.cveIDs) {
				t.Errorf("[%s]->cveIDs: expected: %s, actual: %s", tt.packName, tt.expect.cveIDs, cveIDs)
			}
			if !reflect.DeepEqual(pack.Changelog.Contents, tt.expect.pack.Changelog.Contents) {
				t.Errorf("[%s]->changelog.Contents: expected: %s, actual: %s", tt.packName, tt.expect.pack.Changelog.Contents, pack.Changelog.Contents)
			}
		})
	}
}
