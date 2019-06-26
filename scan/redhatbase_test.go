/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

//  func unixtimeNoerr(s string) time.Time {
//      t, _ := unixtime(s)
//      return t
//  }

func TestParseInstalledPackagesLinesRedhat(t *testing.T) {
	r := newRHEL(config.ServerInfo{})
	r.Distro = config.Distro{Family: config.RedHat}

	var packagetests = []struct {
		in       string
		kernel   models.Kernel
		packages models.Packages
	}{
		{
			in: `openssl	0	1.0.1e	30.el6.11 x86_64
                 Percona-Server-shared-56	1	5.6.19	rel67.0.el6 x84_64
                 kernel 0 2.6.32 696.20.1.el6 x86_64
                 kernel 0 2.6.32 696.20.3.el6 x86_64
				 kernel 0 2.6.32 695.20.3.el6 x86_64`,
			kernel: models.Kernel{},
			packages: models.Packages{
				"openssl": models.Package{
					Name:    "openssl",
					Version: "1.0.1e",
					Release: "30.el6.11",
				},
				"Percona-Server-shared-56": models.Package{
					Name:    "Percona-Server-shared-56",
					Version: "1:5.6.19",
					Release: "rel67.0.el6",
				},
				"kernel": models.Package{
					Name:    "kernel",
					Version: "2.6.32",
					Release: "696.20.3.el6",
				},
			},
		},
		{
			in: `openssl	0	1.0.1e	30.el6.11 x86_64
                 Percona-Server-shared-56	1	5.6.19	rel67.0.el6 x84_64
                 kernel 0 2.6.32 696.20.1.el6 x86_64
                 kernel 0 2.6.32 696.20.3.el6 x86_64
				 kernel 0 2.6.32 695.20.3.el6 x86_64`,
			kernel: models.Kernel{Release: "2.6.32-695.20.3.el6.x86_64"},
			packages: models.Packages{
				"openssl": models.Package{
					Name:    "openssl",
					Version: "1.0.1e",
					Release: "30.el6.11",
				},
				"Percona-Server-shared-56": models.Package{
					Name:    "Percona-Server-shared-56",
					Version: "1:5.6.19",
					Release: "rel67.0.el6",
				},
				"kernel": models.Package{
					Name:    "kernel",
					Version: "2.6.32",
					Release: "695.20.3.el6",
				},
			},
		},
	}

	for _, tt := range packagetests {
		r.Kernel = tt.kernel
		packages, _, err := r.parseInstalledPackages(tt.in)
		if err != nil {
			t.Errorf("Unexpected error: %s", err)
		}
		for name, expectedPack := range tt.packages {
			pack := packages[name]
			if pack.Name != expectedPack.Name {
				t.Errorf("name: expected %s, actual %s", expectedPack.Name, pack.Name)
			}
			if pack.Version != expectedPack.Version {
				t.Errorf("version: expected %s, actual %s", expectedPack.Version, pack.Version)
			}
			if pack.Release != expectedPack.Release {
				t.Errorf("release: expected %s, actual %s", expectedPack.Release, pack.Release)
			}
		}
	}

}
func TestParseScanedPackagesLineRedhat(t *testing.T) {
	r := newRHEL(config.ServerInfo{})

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

func TestParseYumCheckUpdateLine(t *testing.T) {
	r := newCentOS(config.ServerInfo{})
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
	r := newCentOS(config.ServerInfo{})
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
	r := newAmazon(config.ServerInfo{})
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

func TestCheckYumPsInstalled(t *testing.T) {
	r := newCentOS(config.ServerInfo{})
	var tests = []struct {
		in  string
		out bool
	}{
		{
			in: `Loaded plugins: changelog, fastestmirror, ps, remove-with-leaves, show-leaves
Loading mirror speeds from cached hostfile
 * base: ftp.tsukuba.wide.ad.jp
 * extras: ftp.tsukuba.wide.ad.jp
 * updates: ftp.tsukuba.wide.ad.jp
Installed Packages
Name        : yum
Arch        : noarch
Version     : 3.4.3
Release     : 150.el7.centos
Size        : 5.5 M
Repo        : installed
From repo   : anaconda
Summary     : RPM package installer/updater/manager
URL         : http://yum.baseurl.org/
License     : GPLv2+
Description : Yum is a utility that can check for and automatically download and
            : install updated RPM packages. Dependencies are obtained and downloaded
            : automatically, prompting the user for permission as necessary.

Available Packages
Name        : yum
Arch        : noarch
Version     : 3.4.3
Release     : 154.el7.centos.1
Size        : 1.2 M
Repo        : updates/7/x86_64
Summary     : RPM package installer/updater/manager
URL         : http://yum.baseurl.org/
License     : GPLv2+
Description : Yum is a utility that can check for and automatically download and
            : install updated RPM packages. Dependencies are obtained and downloaded
            : automatically, prompting the user for permission as necessary.`,
			out: true,
		},
		{
			in: `Failed to set locale, defaulting to C
Loaded plugins: amazon-id, rhui-lb, search-disabled-repos
Installed Packages
Name        : yum
Arch        : noarch
Version     : 3.4.3
Release     : 154.el7
Size        : 5.5 M
Repo        : installed
From repo   : rhui-REGION-rhel-server-releases
Summary     : RPM package installer/updater/manager
URL         : http://yum.baseurl.org/
License     : GPLv2+
Description : Yum is a utility that can check for and automatically download and
            : install updated RPM packages. Dependencies are obtained and downloaded
            : automatically, prompting the user for permission as necessary.`,
			out: false,
		},
	}

	for _, tt := range tests {
		ok := r.checkYumPsInstalled(tt.in)
		if ok != tt.out {
			t.Errorf("expected: %v\nactual: %v", tt.out, ok)
		}
	}
}

func TestParseYumPS(t *testing.T) {
	r := newCentOS(config.ServerInfo{})
	r.Distro = config.Distro{Family: "centos"}
	r.Packages = models.NewPackages(
		models.Package{
			Name:    "python",
			Version: "2.7.5",
			Release: "34.el7",
			Arch:    "x86_64",
		},
		models.Package{
			Name:    "util-linux",
			Version: "2.23.2",
			Release: "26.el7",
			Arch:    "x86_64",
		},
		models.Package{
			Name:    "wpa_supplicant",
			Version: "1:2.0",
			Release: "17.el7_1",
			Arch:    "x86_64",
		},
		models.Package{
			Name:    "yum",
			Version: "3.4.3",
			Release: "150.el7.centos",
			Arch:    "noarch",
		},
	)

	var tests = []struct {
		in  string
		out models.Packages
	}{
		{
			`       pid proc                  CPU      RSS      State uptime
python-2.7.5-34.el7.x86_64 Upgrade 2.7.5-48.el7.x86_64
       741 tuned                1:54    16 MB   Sleeping:  14 day(s) 21:52:32
     38755 yum                  0:00    42 MB    Running:  00:00
util-linux-2.23.2-26.el7.x86_64 Upgrade 2.23.2-33.el7_3.2.x86_64
       626 agetty               0:00   848 kB   Sleeping:  14 day(s) 21:52:37
       628 agetty               0:00   848 kB   Sleeping:  14 day(s) 21:52:37
1:wpa_supplicant-2.0-17.el7_1.x86_64 Upgrade 1:2.0-21.el7_3.x86_64
       638 wpa_supplicant       0:00   2.6 MB   Sleeping:  14 day(s) 21:52:37
yum-3.4.3-150.el7.centos.noarch
     38755 yum                  0:00    42 MB    Running:  00:00
ps
	 `,
			models.NewPackages(
				models.Package{
					Name:    "python",
					Version: "2.7.5",
					Release: "34.el7",
					Arch:    "x86_64",
					// NewVersion: "2.7.5-",
					// NewRelease: "48.el7.x86_64",
					AffectedProcs: []models.AffectedProcess{
						{
							PID:  "741",
							Name: "tuned",
						},
						{
							PID:  "38755",
							Name: "yum",
						},
					},
				},
				models.Package{
					Name:    "util-linux",
					Version: "2.23.2",
					Release: "26.el7",
					Arch:    "x86_64",
					// NewVersion: "2.7.5",
					// NewRelease: "48.el7.x86_64",
					AffectedProcs: []models.AffectedProcess{
						{
							PID:  "626",
							Name: "agetty",
						},
						{
							PID:  "628",
							Name: "agetty",
						},
					},
				},
				models.Package{
					Name:    "wpa_supplicant",
					Version: "1:2.0",
					Release: "17.el7_1",
					Arch:    "x86_64",
					// NewVersion: "1:2.0",
					// NewRelease: "21.el7_3.x86_64",
					AffectedProcs: []models.AffectedProcess{
						{
							PID:  "638",
							Name: "wpa_supplicant",
						},
					},
				},
			),
		},
		{
			`    pid proc                  CPU      RSS      State uptime
acpid-2.0.19-6.7.amzn1.x86_64
      2388 acpid                0:00   1.4 MB   Sleeping:  21:08
at-3.1.10-48.15.amzn1.x86_64
      2546 atd                  0:00   164 kB   Sleeping:  21:06
cronie-anacron-1.4.4-15.8.amzn1.x86_64
      2637 anacron              0:00   1.5 MB   Sleeping:  13:14
12:dhclient-4.1.1-51.P1.26.amzn1.x86_64
      2061 dhclient             0:00   1.4 MB   Sleeping:  21:10
      2193 dhclient             0:00   2.1 MB   Sleeping:  21:08
mingetty-1.08-5.9.amzn1.x86_64
      2572 mingetty             0:00   1.4 MB   Sleeping:  21:06
      2575 mingetty             0:00   1.4 MB   Sleeping:  21:06
      2578 mingetty             0:00   1.5 MB   Sleeping:  21:06
      2580 mingetty             0:00   1.4 MB   Sleeping:  21:06
      2582 mingetty             0:00   1.4 MB   Sleeping:  21:06
      2584 mingetty             0:00   1.4 MB   Sleeping:  21:06
openssh-server-6.6.1p1-33.66.amzn1.x86_64
      2481 sshd                 0:00   2.6 MB   Sleeping:  21:07
python27-2.7.12-2.120.amzn1.x86_64
      2649 yum                  0:00    35 MB    Running:  00:01
rsyslog-5.8.10-9.26.amzn1.x86_64
      2261 rsyslogd             0:00   2.6 MB   Sleeping:  21:08
udev-173-4.13.amzn1.x86_64
      1528 udevd                0:00   2.5 MB   Sleeping:  21:12
      1652 udevd                0:00   2.1 MB   Sleeping:  21:12
      1653 udevd                0:00   2.0 MB   Sleeping:  21:12
upstart-0.6.5-13.3.13.amzn1.x86_64
         1 init                 0:00   2.5 MB   Sleeping:  21:13
util-linux-2.23.2-33.28.amzn1.x86_64
      2569 agetty               0:00   1.6 MB   Sleeping:  21:06
yum-3.4.3-150.70.amzn1.noarch
      2649 yum                  0:00    35 MB    Running:  00:01
`,
			models.Packages{},
		},
	}

	for _, tt := range tests {
		packages := r.parseYumPS(tt.in)
		for name, ePack := range tt.out {
			if !reflect.DeepEqual(ePack, packages[name]) {
				e := pp.Sprintf("%v", ePack)
				a := pp.Sprintf("%v", packages[name])
				t.Errorf("expected %s, actual %s", e, a)
			}
		}
	}
}

func TestParseNeedsRestarting(t *testing.T) {
	r := newCentOS(config.ServerInfo{})
	r.Distro = config.Distro{Family: "centos"}

	var tests = []struct {
		in  string
		out []models.NeedRestartProcess
	}{
		{
			`1 : /usr/lib/systemd/systemd --switched-root --system --deserialize 21
437 : /usr/sbin/NetworkManager --no-daemon`,
			[]models.NeedRestartProcess{
				{
					PID:     "437",
					Path:    "/usr/sbin/NetworkManager --no-daemon",
					HasInit: true,
				},
			},
		},
	}

	for _, tt := range tests {
		procs := r.parseNeedsRestarting(tt.in)
		if !reflect.DeepEqual(tt.out, procs) {
			t.Errorf("expected %#v, actual %#v", tt.out, procs)
		}
	}
}
