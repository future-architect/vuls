package scanner

import (
	"reflect"
	"testing"

	"github.com/k0kubun/pp"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

func TestScanUpdatablePackages(t *testing.T) {
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		args    args
		want    models.Packages
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				stdout: `S | Repository                                  | Name                          | Current Version             | Available Version           | Arch
--+---------------------------------------------+-------------------------------+-----------------------------+-----------------------------+-------
v | SLES12-SP2-Updates                          | SUSEConnect                   | 0.3.0-19.8.1                | 0.3.1-19.11.2               | x86_64
v | SLES12-SP2-Updates                          | SuSEfirewall2                 | 3.6.312-2.3.1               | 3.6.312-2.10.1              | noarch
v | Clone of SLES11-SP3-Updates for x86_64 | ConsoleKit | 0.2.10-64.65.1 | 0.2.10-64.69.1 | x86_64`,
			},
			want: models.Packages{
				"SUSEConnect": {
					Name:       "SUSEConnect",
					NewVersion: "0.3.1",
					NewRelease: "19.11.2",
					Arch:       "x86_64",
				},
				"SuSEfirewall2": {
					Name:       "SuSEfirewall2",
					NewVersion: "3.6.312",
					NewRelease: "2.10.1",
					Arch:       "noarch",
				},
				"ConsoleKit": {
					Name:       "ConsoleKit",
					NewVersion: "0.2.10",
					NewRelease: "64.69.1",
					Arch:       "x86_64",
				},
			},
		},
		{
			name: "start new line",
			args: args{
				stdout: `
S | Repository | Name | Current Version | Available Version | Arch
--+--------------------------------------------------------------+-----------------------+-------------------------------+--------------------------------+-------
v | Update repository with updates from SUSE Linux Enterprise 15 | git-core | 2.43.0-150600.1.10 | 2.43.0-150600.3.3.1 | x86_64`,
			},
			want: models.Packages{
				"git-core": {
					Name:       "git-core",
					NewVersion: "2.43.0",
					NewRelease: "150600.3.3.1",
					Arch:       "x86_64",
				},
			},
		},
		{
			name: "table header",
			args: args{
				stdout: `S  | Repository                                                   | Name     | Current Version | Available Version | Arch
---+--------------------------------------------------------------+----------+-----------------+-------------------+-------
v  | Update repository with updates from SUSE Linux Enterprise 15 | iproute2 | 5.14-150400.1.8 | 6.4-150600.7.3.1  | x86_64`,
			},
			want: models.Packages{
				"iproute2": {
					Name:       "iproute2",
					NewVersion: "6.4",
					NewRelease: "150600.7.3.1",
					Arch:       "x86_64",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (newSUSE(config.ServerInfo{Distro: config.Distro{Family: "sles"}})).parseZypperLULines(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("suse.parseZypperLULines() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("suse.parseZypperLULines() = %v, want %v", got, tt.want)
			}
		})
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

func Test_suse_rebootRequired(t *testing.T) {
	tests := []struct {
		name         string
		kernel       models.Kernel
		result       execResult
		wantPkgNames []string
		want         bool
		wantErr      bool
	}{
		{
			name:   "kernel-default no-reboot",
			kernel: models.Kernel{Release: "6.12.0-160000.5-default"},
			result: execResult{
				Stdout: `kernel-default-6.12.0-160000.5.1.x86_64      Thu May  7 06:00:00 2026
package kernel-default-base is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         false,
		},
		{
			name:   "kernel-default needs-reboot",
			kernel: models.Kernel{Release: "6.12.0-160000.5-default"},
			result: execResult{
				Stdout: `kernel-default-6.12.0-160000.29.1.x86_64     Thu May  7 06:10:00 2026
kernel-default-6.12.0-160000.5.1.x86_64      Thu May  7 06:00:00 2026
package kernel-default-base is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         true,
		},
		{
			name:   "kernel-default needs-reboot, the running kernel release is a prefix of the last installed one",
			kernel: models.Kernel{Release: "6.12.0-160000.4-default"},
			result: execResult{
				Stdout: `kernel-default-6.12.0-160000.41.1.x86_64     Tue Nov 24 10:00:00 2026
kernel-default-6.12.0-160000.4.1.x86_64      Thu May  7 06:00:00 2026
package kernel-default-base is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         true,
		},
		{
			name:   "kernel-default-base no-reboot",
			kernel: models.Kernel{Release: "6.12.0-160000.41-default"},
			result: execResult{
				Stdout: `kernel-default-base-6.12.0-160000.41.1.160000.2.33.x86_64 Tue Nov 24 09:51:20 2026
kernel-default-base-6.12.0-160000.40.1.160000.2.29.x86_64 Tue Nov 24 09:51:07 2026
package kernel-default is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         false,
		},
		{
			name:   "kernel-default-base needs-reboot",
			kernel: models.Kernel{Release: "6.12.0-160000.40-default"},
			result: execResult{
				Stdout: `kernel-default-base-6.12.0-160000.41.1.160000.2.33.x86_64 Tue Nov 24 09:51:20 2026
kernel-default-base-6.12.0-160000.40.1.160000.2.29.x86_64 Tue Nov 24 09:51:07 2026
package kernel-default is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         true,
		},
		{
			name:   "kernel-default installed after the running kernel-default-base",
			kernel: models.Kernel{Release: "6.12.0-160000.40-default"},
			result: execResult{
				Stdout: `kernel-default-6.12.0-160000.41.1.x86_64     Tue Nov 24 10:00:00 2026
kernel-default-base-6.12.0-160000.40.1.160000.2.29.x86_64 Tue Nov 24 09:51:07 2026`,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         true,
		},
		{
			name:   "kernel-azure no-reboot",
			kernel: models.Kernel{Release: "6.4.0-150600.8.8-azure"},
			result: execResult{
				Stdout: `kernel-azure-6.4.0-150600.8.8.1.x86_64       Mon 01 Jul 2024 00:00:00 AM UTC
package kernel-azure-base is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-azure", "kernel-azure-base"},
			want:         false,
		},
		{
			name:   "kernel not installed",
			kernel: models.Kernel{Release: "6.8.0-138-generic"},
			result: execResult{
				Stdout: `package kernel-generic-base is not installed
package kernel-generic is not installed`,
				ExitStatus: 2,
			},
			wantPkgNames: []string{"kernel-generic", "kernel-generic-base"},
			want:         false,
		},
		{
			name:   "kernel-default and kernel-default-base of the same version no-reboot",
			kernel: models.Kernel{Release: "4.4.74-92.35-default"},
			result: execResult{
				Stdout: `kernel-default-base-4.4.74-92.35.1.x86_64    Wed 12 Jul 2017 01:02:03 AM UTC
kernel-default-4.4.74-92.35.1.x86_64         Wed 12 Jul 2017 01:02:03 AM UTC
kernel-default-base-4.4.59-92.20.2.x86_64    Thu 01 Jun 2017 01:02:03 AM UTC
kernel-default-4.4.59-92.20.2.x86_64         Thu 01 Jun 2017 01:02:03 AM UTC`,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         false,
		},
		{
			name:   "kernel-default without arch needs-reboot",
			kernel: models.Kernel{Release: "3.0.101-108.84-default"},
			result: execResult{
				Stdout: `kernel-default-3.0.101-108.87.1               Thu 07 Mar 2019 01:02:03 AM UTC
kernel-default-3.0.101-108.84.1               Wed 16 Jan 2019 01:02:03 AM UTC
package kernel-default-base is not installed`,
				ExitStatus: 1,
			},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			want:         true,
		},
		{
			name:         "rpm failed",
			kernel:       models.Kernel{Release: "6.12.0-160000.41-default"},
			result:       execResult{ExitStatus: 127},
			wantPkgNames: []string{"kernel-default", "kernel-default-base"},
			wantErr:      true,
		},
		{
			name:   "unknown kernel flavor",
			kernel: models.Kernel{Release: "6.12.1"},
			want:   false,
		},
		{
			name:   "unexpected kernel flavor",
			kernel: models.Kernel{Release: "6.12.0-1-x';touch /tmp/pwn;'"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &suse{redhatBase: redhatBase{base: base{osPackages: osPackages{Kernel: tt.kernel}, log: logging.NewIODiscardLogger()}}}
			var gotPkgNames []string
			got, err := o.rebootRequired(func(pkgNames []string) execResult {
				gotPkgNames = pkgNames
				return tt.result
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("suse.rebootRequired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotPkgNames, tt.wantPkgNames) {
				t.Errorf("suse.rebootRequired() pkgNames = %v, want %v", gotPkgNames, tt.wantPkgNames)
			}
			if got != tt.want {
				t.Errorf("suse.rebootRequired() = %v, want %v", got, tt.want)
			}
		})
	}
}
