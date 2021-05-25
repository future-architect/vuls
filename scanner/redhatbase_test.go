package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

//  func unixtimeNoerr(s string) time.Time {
//      t, _ := unixtime(s)
//      return t
//  }

func TestParseInstalledPackagesLinesRedhat(t *testing.T) {
	r := newRHEL(config.ServerInfo{})
	r.Distro = config.Distro{Family: constant.RedHat}

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
kernel 0 2.6.32 695.20.3.el6 x86_64
kernel-devel 0 2.6.32 696.20.1.el6 x86_64
kernel-devel 0 2.6.32 696.20.3.el6 x86_64
kernel-devel 0 2.6.32 695.20.3.el6 x86_64`,
			kernel: models.Kernel{Release: "2.6.32-696.20.3.el6.x86_64"},
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
				"kernel-devel": models.Package{
					Name:    "kernel-devel",
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
kernel 0 2.6.32 695.20.3.el6 x86_64
kernel-devel 0 2.6.32 696.20.1.el6 x86_64
kernel-devel 0 2.6.32 696.20.3.el6 x86_64
kernel-devel 0 2.6.32 695.20.3.el6 x86_64`,
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
				"kernel-devel": models.Package{
					Name:    "kernel-devel",
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
func TestParseInstalledPackagesLine(t *testing.T) {
	r := newRHEL(config.ServerInfo{})

	var packagetests = []struct {
		in   string
		pack models.Package
		err  bool
	}{
		{
			"openssl	0	1.0.1e	30.el6.11 x86_64",
			models.Package{
				Name:    "openssl",
				Version: "1.0.1e",
				Release: "30.el6.11",
			},
			false,
		},
		{
			"Percona-Server-shared-56	1	5.6.19	rel67.0.el6 x84_64",
			models.Package{
				Name:    "Percona-Server-shared-56",
				Version: "1:5.6.19",
				Release: "rel67.0.el6",
			},
			false,
		},
	}

	for i, tt := range packagetests {
		p, err := r.parseInstalledPackagesLine(tt.in)
		if err == nil && tt.err {
			t.Errorf("Expected err not occurred: %d", i)
		}
		if err != nil && !tt.err {
			t.Errorf("UnExpected err not occurred: %d", i)
		}
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
			t.Errorf("Error has occurred, err: %+v\ntt.in: %v", err, tt.in)
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
			t.Errorf("Error has occurred, err: %+v\ntt.in: %v", err, tt.in)
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
	r := newRHEL(config.ServerInfo{})
	r.Distro = config.Distro{Family: "centos"}

	var tests = []struct {
		in  string
		out []models.NeedRestartProcess
	}{
		{
			`1 : /usr/lib/systemd/systemd --switched-root --system --deserialize 21kk
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

func Test_redhatBase_parseDnfModuleList(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name       string
		args       args
		wantLabels []string
		wantErr    bool
	}{
		{
			name: "Success",
			args: args{
				stdout: `Red Hat Enterprise Linux 8 for x86_64 - AppStream from RHUI (RPMs)
Name                                     Stream                                         Profiles                                          Summary
virt                 rhel [d][e] common [d]                               Virtualization module
nginx                                    1.14 [d][e]                                    common [d] [i]                                    nginx webserver

Hint: [d]efault, [e]nabled, [x]disabled, [i]nstalled`,
			},
			wantLabels: []string{
				"nginx:1.14",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhatBase{}
			gotLabels, err := o.parseDnfModuleList(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseDnfModuleList() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotLabels, tt.wantLabels) {
				t.Errorf("redhatBase.parseDnfModuleList() = %v, want %v", gotLabels, tt.wantLabels)
			}
		})
	}
}

func Test_redhatBase_parseRpmQfLine(t *testing.T) {
	type fields struct {
		base base
		sudo rootPriv
	}
	type args struct {
		line string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantPkg     *models.Package
		wantIgnored bool
		wantErr     bool
	}{
		{
			name:        "permission denied will be ignored",
			fields:      fields{base: base{}},
			args:        args{line: "/tmp/hogehoge Permission denied"},
			wantPkg:     nil,
			wantIgnored: true,
			wantErr:     false,
		},
		{
			name:        "is not owned by any package",
			fields:      fields{base: base{}},
			args:        args{line: "/tmp/hogehoge is not owned by any package"},
			wantPkg:     nil,
			wantIgnored: true,
			wantErr:     false,
		},
		{
			name:        "No such file or directory will be ignored",
			fields:      fields{base: base{}},
			args:        args{line: "/tmp/hogehoge No such file or directory"},
			wantPkg:     nil,
			wantIgnored: true,
			wantErr:     false,
		},
		{
			name:   "valid line",
			fields: fields{base: base{}},
			args: args{line: "Percona-Server-shared-56	1	5.6.19	rel67.0.el6 x86_64"},
			wantPkg: &models.Package{
				Name:    "Percona-Server-shared-56",
				Version: "1:5.6.19",
				Release: "rel67.0.el6",
				Arch:    "x86_64",
			},
			wantIgnored: false,
			wantErr:     false,
		},
		{
			name:        "err",
			fields:      fields{base: base{}},
			args:        args{line: "/tmp/hogehoge something unknown format"},
			wantPkg:     nil,
			wantIgnored: false,
			wantErr:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhatBase{
				base: tt.fields.base,
				sudo: tt.fields.sudo,
			}
			gotPkg, gotIgnored, err := o.parseRpmQfLine(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseRpmQfLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPkg, tt.wantPkg) {
				t.Errorf("redhatBase.parseRpmQfLine() gotPkg = %v, want %v", gotPkg, tt.wantPkg)
			}
			if gotIgnored != tt.wantIgnored {
				t.Errorf("redhatBase.parseRpmQfLine() gotIgnored = %v, want %v", gotIgnored, tt.wantIgnored)
			}
		})
	}
}

func Test_redhatBase_rebootRequired(t *testing.T) {
	type fields struct {
		base base
		sudo rootPriv
	}
	type args struct {
		fn func(s string) execResult
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "uek kernel no-reboot",
			fields: fields{
				base: base{
					osPackages: osPackages{
						Kernel: models.Kernel{
							Release: "5.4.17-2102.200.13.el7uek.x86_64",
						},
					},
				},
			},
			args: args{
				fn: func(s string) execResult {
					return execResult{
						Stdout: `kernel-uek-5.4.17-2102.200.13.el7uek.x86_64   Mon 05 Apr 2021 04:52:06 PM UTC
	kernel-uek-4.14.35-2047.501.2.el7uek.x86_64   Mon 05 Apr 2021 04:49:39 PM UTC
	kernel-uek-4.14.35-1902.10.2.1.el7uek.x86_64  Wed 29 Jan 2020 05:04:52 PM UTC`,
					}
				},
			},
			want:    false,
			wantErr: false,
		},
		{
			name: "uek kernel needs-reboot",
			fields: fields{
				base: base{
					osPackages: osPackages{
						Kernel: models.Kernel{
							Release: "4.14.35-2047.501.2.el7uek.x86_64",
						},
					},
				},
			},
			args: args{
				fn: func(s string) execResult {
					return execResult{
						Stdout: `kernel-uek-5.4.17-2102.200.13.el7uek.x86_64   Mon 05 Apr 2021 04:52:06 PM UTC
	kernel-uek-4.14.35-2047.501.2.el7uek.x86_64   Mon 05 Apr 2021 04:49:39 PM UTC
	kernel-uek-4.14.35-1902.10.2.1.el7uek.x86_64  Wed 29 Jan 2020 05:04:52 PM UTC`,
					}
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "kerne needs-reboot",
			fields: fields{
				base: base{
					osPackages: osPackages{
						Kernel: models.Kernel{
							Release: "3.10.0-1062.12.1.el7.x86_64",
						},
					},
				},
			},
			args: args{
				fn: func(s string) execResult {
					return execResult{
						Stdout: `kernel-3.10.0-1160.24.1.el7.x86_64            Mon 26 Apr 2021 10:13:54 AM UTC
kernel-3.10.0-1062.12.1.el7.x86_64            Sat 29 Feb 2020 12:09:00 PM UTC`,
					}
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "kerne no-reboot",
			fields: fields{
				base: base{
					osPackages: osPackages{
						Kernel: models.Kernel{
							Release: "3.10.0-1160.24.1.el7.x86_64",
						},
					},
				},
			},
			args: args{
				fn: func(s string) execResult {
					return execResult{
						Stdout: `kernel-3.10.0-1160.24.1.el7.x86_64            Mon 26 Apr 2021 10:13:54 AM UTC
kernel-3.10.0-1062.12.1.el7.x86_64            Sat 29 Feb 2020 12:09:00 PM UTC`,
					}
				},
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhatBase{
				base: tt.fields.base,
				sudo: tt.fields.sudo,
			}
			got, err := o.rebootRequired(tt.args.fn)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.rebootRequired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("redhatBase.rebootRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}
