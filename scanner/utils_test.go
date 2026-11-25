package scanner

import (
	"testing"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func Test_isRunningKernel(t *testing.T) {
	type args struct {
		pack    models.Package
		family  string
		release string
		kernel  models.Kernel
	}
	tests := []struct {
		name         string
		args         args
		wantIsKernel bool
		wantRunning  bool
	}{
		{
			name: "Amazon not kernel",
			args: args{
				pack: models.Package{
					Name:    "kernel-livepatch-4.14.165-131.185",
					Version: "1.0",
					Release: "0.amzn1",
					Arch:    "x86_64",
				},
				family:  constant.Amazon,
				release: "1",
				kernel: models.Kernel{
					Release: "4.9.43-17.38.amzn1.x86_64",
				},
			},
			wantIsKernel: false,
			wantRunning:  false,
		},
		{
			name: "Amazon kernel and running",
			args: args{
				pack: models.Package{
					Name:    "kernel",
					Version: "4.9.43",
					Release: "17.38.amzn1",
					Arch:    "x86_64",
				},
				family:  constant.Amazon,
				release: "1",
				kernel: models.Kernel{
					Release: "4.9.43-17.38.amzn1.x86_64",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "Amazon kernel but not running",
			args: args{
				pack: models.Package{
					Name:    "kernel",
					Version: "4.9.38",
					Release: "16.35.amzn1",
					Arch:    "x86_64",
				},
				family:  constant.Amazon,
				release: "1",
				kernel: models.Kernel{
					Release: "4.9.43-17.38.amzn1.x86_64",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUES not kernel",
			args: args{
				pack: models.Package{
					Name:    "bash",
					Version: "4.4",
					Release: "19.6.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "12.2",
				kernel: models.Kernel{
					Release: "4.4.74-92.35-default",
				},
			},
			wantIsKernel: false,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default",
					Version: "4.4.74",
					Release: "92.35.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "12.2",
				kernel: models.Kernel{
					Release: "4.4.74-92.35-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUES kernel but not running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default",
					Version: "4.4.59",
					Release: "92.20.2",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "12.2",
				kernel: models.Kernel{
					Release: "4.4.74-92.35-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-default-base and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-base",
					Version: "6.12.0",
					Release: "160000.41.1.160000.2.33",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.0",
				kernel: models.Kernel{
					Release: "6.12.0-160000.41-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-default-base but not running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-base",
					Version: "6.12.0",
					Release: "160000.40.1.160000.2.29",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.0",
				kernel: models.Kernel{
					Release: "6.12.0-160000.41-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-default-base but not running, the running kernel release is a prefix",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-base",
					Version: "6.12.0",
					Release: "160000.41.1.160000.2.33",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.0",
				kernel: models.Kernel{
					Release: "6.12.0-160000.4-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-default-base but another flavor is running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-base",
					Version: "6.4.0",
					Release: "150600.8.8.1.150600.4.3.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.8.8-azure",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-default-base, subpackage of kernel-default, and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-base",
					Version: "4.4.74",
					Release: "92.35.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "12.2",
				kernel: models.Kernel{
					Release: "4.4.74-92.35-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-azure and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-azure",
					Version: "6.4.0",
					Release: "150600.8.58.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.8.58-azure",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-azure but not running",
			args: args{
				pack: models.Package{
					Name:    "kernel-azure",
					Version: "6.4.0",
					Release: "150600.8.55.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.8.58-azure",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-default but another flavor is running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default",
					Version: "6.12.0",
					Release: "160000.41.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.0",
				kernel: models.Kernel{
					Release: "6.12.0-160000.41-azure",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-rt_debug but kernel-rt is running",
			args: args{
				pack: models.Package{
					Name:    "kernel-rt_debug",
					Version: "6.4.0",
					Release: "150600.10.61.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.10.61-rt",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-rt_debug and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-rt_debug",
					Version: "6.4.0",
					Release: "150600.10.61.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.10.61-rt_debug",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-nvidia64kb but kernel-nvidia is running",
			args: args{
				pack: models.Package{
					Name:    "kernel-nvidia64kb",
					Version: "6.12.0",
					Release: "160100.7.1",
					Arch:    "aarch64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.1",
				kernel: models.Kernel{
					Release: "6.12.0-160100.7-nvidia",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-longterm and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-longterm",
					Version: "6.18.64",
					Release: "1.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSE,
				release: "tumbleweed",
				kernel: models.Kernel{
					Release: "6.18.64-1-longterm",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-default-devel and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-devel",
					Version: "6.4.0",
					Release: "150600.23.103.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-default-livepatch but not running",
			args: args{
				pack: models.Package{
					Name:    "kernel-default-livepatch",
					Version: "6.4.0",
					Release: "150600.23.100.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-rt-extra and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-rt-extra",
					Version: "6.12.0",
					Release: "160000.41.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.0",
				kernel: models.Kernel{
					Release: "6.12.0-160000.41-rt",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-devel and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-devel",
					Version: "6.4.0",
					Release: "150600.23.103.1",
					Arch:    "noarch",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel-devel but another branch is running",
			args: args{
				pack: models.Package{
					Name:    "kernel-devel",
					Version: "6.4.0",
					Release: "150600.23.103.1",
					Arch:    "noarch",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.8.58-azure",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-source-azure and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-source-azure",
					Version: "6.4.0",
					Release: "150600.8.58.1",
					Arch:    "noarch",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.8.58-azure",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel of a flavor unknown to vuls and running",
			args: args{
				pack: models.Package{
					Name:    "kernel-example-devel",
					Version: "6.4.0",
					Release: "150600.23.103.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-example",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
		{
			name: "SUSE kernel of a flavor unknown to vuls and not running",
			args: args{
				pack: models.Package{
					Name:    "kernel-example",
					Version: "6.4.0",
					Release: "150600.23.103.1",
					Arch:    "x86_64",
				},
				family:  constant.SUSEEnterpriseServer,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: false,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-default, but the running kernel is of a container host",
			args: args{
				pack: models.Package{
					Name:    "kernel-default",
					Version: "6.12.0",
					Release: "160000.41.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "16.0",
				kernel: models.Kernel{
					Release: "5.14.0-427.13.1.el9_4.x86_64",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-firmware is not a kernel",
			args: args{
				pack: models.Package{
					Name:    "kernel-firmware-nvidia-gspx-G06",
					Version: "550.100",
					Release: "150600.3.7.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: false,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel-macros is not a kernel",
			args: args{
				pack: models.Package{
					Name:    "kernel-macros",
					Version: "6.4.0",
					Release: "150600.23.103.1",
					Arch:    "noarch",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: false,
			wantRunning:  false,
		},
		{
			name: "SUSE kernel livepatch module is not a kernel",
			args: args{
				pack: models.Package{
					Name:    "kernel-livepatch-6_4_0-150600_23_103-default",
					Version: "1",
					Release: "150600.13.3.1",
					Arch:    "x86_64",
				},
				family:  constant.OpenSUSELeap,
				release: "15.6",
				kernel: models.Kernel{
					Release: "6.4.0-150600.23.103-default",
				},
			},
			wantIsKernel: false,
			wantRunning:  false,
		},
		{
			name: "kernel is kernel-debug, but pack is kernel",
			args: args{
				pack: models.Package{
					Name:    "kernel",
					Version: "5.14.0",
					Release: "70.13.1.el9_0",
					Arch:    "x86_64",
				},
				family:  constant.RedHat,
				release: "9.0",
				kernel: models.Kernel{
					Release: "5.14.0-427.13.1.el9_4.x86_64+debug",
				},
			},
			wantIsKernel: true,
			wantRunning:  false,
		},
		{
			name: "old redhat kernel release style",
			args: args{
				pack: models.Package{
					Name:    "kernel-debug",
					Version: "2.6.18",
					Release: "419.el5",
					Arch:    "x86_64",
				},
				family:  constant.RedHat,
				release: "5.11",
				kernel: models.Kernel{
					Release: "2.6.18-419.el5debug",
				},
			},
			wantIsKernel: true,
			wantRunning:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIsKernel, gotRunning := isRunningKernel(tt.args.pack, tt.args.family, tt.args.release, tt.args.kernel)
			if gotIsKernel != tt.wantIsKernel {
				t.Errorf("isRunningKernel() gotIsKernel = %v, want %v", gotIsKernel, tt.wantIsKernel)
			}
			if gotRunning != tt.wantRunning {
				t.Errorf("isRunningKernel() gotRunning = %v, want %v", gotRunning, tt.wantRunning)
			}
		})
	}
}
