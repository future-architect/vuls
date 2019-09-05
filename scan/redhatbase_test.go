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
