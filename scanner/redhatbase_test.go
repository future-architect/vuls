package scanner

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

func Test_redhatBase_parseInstalledPackages(t *testing.T) {
	type fields struct {
		base base
		sudo rootPriv
	}
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantbps models.Packages
		wantsps models.SrcPackages
		wantErr bool
	}{
		{
			name: "kernel not set",
			fields: fields{base: base{
				Distro: config.Distro{Family: constant.Alma, Release: "9.0"},
				log:    logging.NewIODiscardLogger(),
			}},
			args: args{
				stdout: `dnf 0 4.14.0 17.el9.alma.1 noarch dnf-4.14.0-17.el9.alma.1.src.rpm (none)
nginx 1 1.24.0 4.module_el9.5.0+122+220a1c6b.alma.1 x86_64 nginx-1.24.0-4.module_el9.5.0+122+220a1c6b.alma.1.src.rpm nginx:1.24:9050020241004144538:8cf767d6
kernel-core 0 5.14.0 70.13.1.el9_0 x86_64 kernel-5.14.0-70.13.1.el9_0.src.rpm (none)
kernel 0 5.14.0 70.13.1.el9_0 x86_64 kernel-5.14.0-70.13.1.el9_0.src.rpm (none)
kernel-core 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)
kernel 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)`,
			},
			wantbps: models.Packages{
				"dnf": models.Package{
					Name:    "dnf",
					Version: "4.14.0",
					Release: "17.el9.alma.1",
					Arch:    "noarch",
				},
				"nginx": models.Package{
					Name:            "nginx",
					Version:         "1:1.24.0",
					Release:         "4.module_el9.5.0+122+220a1c6b.alma.1",
					Arch:            "x86_64",
					ModularityLabel: "nginx:1.24:9050020241004144538:8cf767d6",
				},
				"kernel": models.Package{
					Name:    "kernel",
					Version: "5.14.0",
					Release: "503.15.1.el9_5",
					Arch:    "x86_64",
				},
				"kernel-core": models.Package{
					Name:    "kernel-core",
					Version: "5.14.0",
					Release: "503.15.1.el9_5",
					Arch:    "x86_64",
				},
			},
			wantsps: models.SrcPackages{
				"dnf": models.SrcPackage{
					Name:        "dnf",
					Version:     "4.14.0-17.el9.alma.1",
					Arch:        "src",
					BinaryNames: []string{"dnf"},
				},
				"nginx": models.SrcPackage{
					Name:        "nginx",
					Version:     "1:1.24.0-4.module_el9.5.0+122+220a1c6b.alma.1",
					Arch:        "src",
					BinaryNames: []string{"nginx"},
				},
				"kernel": models.SrcPackage{
					Name:        "kernel",
					Version:     "5.14.0-503.15.1.el9_5",
					Arch:        "src",
					BinaryNames: []string{"kernel", "kernel-core"},
				},
			},
		},
		{
			name: "kernel set",
			fields: fields{base: base{
				Distro:     config.Distro{Family: constant.Alma, Release: "9.0"},
				osPackages: osPackages{Kernel: models.Kernel{Release: "5.14.0-70.13.1.el9_0.x86_64"}},
				log:        logging.NewIODiscardLogger(),
			}},
			args: args{
				stdout: `dnf 0 4.14.0 17.el9.alma.1 noarch dnf-4.14.0-17.el9.alma.1.src.rpm (none)
nginx 1 1.24.0 4.module_el9.5.0+122+220a1c6b.alma.1 x86_64 nginx-1.24.0-4.module_el9.5.0+122+220a1c6b.alma.1.src.rpm nginx:1.24:9050020241004144538:8cf767d6
kernel-core 0 5.14.0 70.13.1.el9_0 x86_64 kernel-5.14.0-70.13.1.el9_0.src.rpm (none)
kernel 0 5.14.0 70.13.1.el9_0 x86_64 kernel-5.14.0-70.13.1.el9_0.src.rpm (none)
kernel-core 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)
kernel 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)`,
			},
			wantbps: models.Packages{
				"dnf": models.Package{
					Name:    "dnf",
					Version: "4.14.0",
					Release: "17.el9.alma.1",
					Arch:    "noarch",
				},
				"nginx": models.Package{
					Name:            "nginx",
					Version:         "1:1.24.0",
					Release:         "4.module_el9.5.0+122+220a1c6b.alma.1",
					Arch:            "x86_64",
					ModularityLabel: "nginx:1.24:9050020241004144538:8cf767d6",
				},
				"kernel": models.Package{
					Name:    "kernel",
					Version: "5.14.0",
					Release: "70.13.1.el9_0",
					Arch:    "x86_64",
				},
				"kernel-core": models.Package{
					Name:    "kernel-core",
					Version: "5.14.0",
					Release: "70.13.1.el9_0",
					Arch:    "x86_64",
				},
			},
			wantsps: models.SrcPackages{
				"dnf": models.SrcPackage{
					Name:        "dnf",
					Version:     "4.14.0-17.el9.alma.1",
					Arch:        "src",
					BinaryNames: []string{"dnf"},
				},
				"nginx": models.SrcPackage{
					Name:        "nginx",
					Version:     "1:1.24.0-4.module_el9.5.0+122+220a1c6b.alma.1",
					Arch:        "src",
					BinaryNames: []string{"nginx"},
				},
				"kernel": models.SrcPackage{
					Name:        "kernel",
					Version:     "5.14.0-70.13.1.el9_0",
					Arch:        "src",
					BinaryNames: []string{"kernel", "kernel-core"},
				},
			},
		},
		{
			name: "debug kernel",
			fields: fields{base: base{
				Distro:     config.Distro{Family: constant.Alma, Release: "9.0"},
				osPackages: osPackages{Kernel: models.Kernel{Release: "5.14.0-503.15.1.el9_5.x86_64+debug"}},
				log:        logging.NewIODiscardLogger(),
			}},
			args: args{
				stdout: `kernel-core 0 5.14.0 70.13.1.el9_0 x86_64 kernel-5.14.0-70.13.1.el9_0.src.rpm (none)
kernel 0 5.14.0 70.13.1.el9_0 x86_64 kernel-5.14.0-70.13.1.el9_0.src.rpm (none)
kernel-core 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)
kernel 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)
kernel-debug-core 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)
kernel-debug 0 5.14.0 503.15.1.el9_5 x86_64 kernel-5.14.0-503.15.1.el9_5.src.rpm (none)`,
			},
			wantbps: models.Packages{
				"kernel-debug": models.Package{
					Name:    "kernel-debug",
					Version: "5.14.0",
					Release: "503.15.1.el9_5",
					Arch:    "x86_64",
				},
				"kernel-debug-core": models.Package{
					Name:    "kernel-debug-core",
					Version: "5.14.0",
					Release: "503.15.1.el9_5",
					Arch:    "x86_64",
				},
			},
			wantsps: models.SrcPackages{
				"kernel": models.SrcPackage{
					Name:        "kernel",
					Version:     "5.14.0-503.15.1.el9_5",
					Arch:        "src",
					BinaryNames: []string{"kernel-debug", "kernel-debug-core"},
				},
			},
		},
		{
			name: "amazon 2 (rpm -qa)",
			fields: fields{base: base{
				Distro: config.Distro{Family: constant.Amazon, Release: "2 (Karoo)"},
				log:    logging.NewIODiscardLogger(),
			}},
			args: args{
				stdout: `yum-utils 0 1.1.31 46.amzn2.0.1 noarch yum-utils-1.1.31-46.amzn2.0.1.src.rpm
zlib 0 1.2.7 19.amzn2.0.3 x86_64 zlib-1.2.7-19.amzn2.0.3.src.rpm
java-1.8.0-amazon-corretto 1 1.8.0_432.b06 1.amzn2 x86_64 java-1.8.0-amazon-corretto-1.8.0_432.b06-1.amzn2.src.rpm`,
			},
			wantbps: models.Packages{
				"yum-utils": models.Package{
					Name:    "yum-utils",
					Version: "1.1.31",
					Release: "46.amzn2.0.1",
					Arch:    "noarch",
				},
				"zlib": models.Package{
					Name:    "zlib",
					Version: "1.2.7",
					Release: "19.amzn2.0.3",
					Arch:    "x86_64",
				},
				"java-1.8.0-amazon-corretto": models.Package{
					Name:    "java-1.8.0-amazon-corretto",
					Version: "1:1.8.0_432.b06",
					Release: "1.amzn2",
					Arch:    "x86_64",
				},
			},
			wantsps: models.SrcPackages{
				"yum-utils": models.SrcPackage{
					Name:        "yum-utils",
					Version:     "1.1.31-46.amzn2.0.1",
					Arch:        "src",
					BinaryNames: []string{"yum-utils"},
				},
				"zlib": models.SrcPackage{
					Name:        "zlib",
					Version:     "1.2.7-19.amzn2.0.3",
					Arch:        "src",
					BinaryNames: []string{"zlib"},
				},
				"java-1.8.0-amazon-corretto": models.SrcPackage{
					Name:        "java-1.8.0-amazon-corretto",
					Version:     "1:1.8.0_432.b06-1.amzn2",
					Arch:        "src",
					BinaryNames: []string{"java-1.8.0-amazon-corretto"},
				},
			},
		},
		{
			name: "amazon 2 (repoquery)",
			fields: fields{base: base{
				Distro: config.Distro{Family: constant.Amazon, Release: "2 (Karoo)"},
				log:    logging.NewIODiscardLogger(),
			}},
			args: args{
				stdout: `yum-utils 0 1.1.31 46.amzn2.0.1 noarch yum-utils-1.1.31-46.amzn2.0.1.src.rpm @amzn2-core
zlib 0 1.2.7 19.amzn2.0.3 x86_64 zlib-1.2.7-19.amzn2.0.3.src.rpm installed
java-1.8.0-amazon-corretto 1 1.8.0_432.b06 1.amzn2 x86_64 java-1.8.0-amazon-corretto-1.8.0_432.b06-1.amzn2.src.rpm @amzn2extra-corretto8`,
			},
			wantbps: models.Packages{
				"yum-utils": models.Package{
					Name:       "yum-utils",
					Version:    "1.1.31",
					Release:    "46.amzn2.0.1",
					Arch:       "noarch",
					Repository: "amzn2-core",
				},
				"zlib": models.Package{
					Name:       "zlib",
					Version:    "1.2.7",
					Release:    "19.amzn2.0.3",
					Arch:       "x86_64",
					Repository: "amzn2-core",
				},
				"java-1.8.0-amazon-corretto": models.Package{
					Name:       "java-1.8.0-amazon-corretto",
					Version:    "1:1.8.0_432.b06",
					Release:    "1.amzn2",
					Arch:       "x86_64",
					Repository: "amzn2extra-corretto8",
				},
			},
			wantsps: models.SrcPackages{
				"yum-utils": models.SrcPackage{
					Name:        "yum-utils",
					Version:     "1.1.31-46.amzn2.0.1",
					Arch:        "src",
					BinaryNames: []string{"yum-utils"},
				},
				"zlib": models.SrcPackage{
					Name:        "zlib",
					Version:     "1.2.7-19.amzn2.0.3",
					Arch:        "src",
					BinaryNames: []string{"zlib"},
				},
				"java-1.8.0-amazon-corretto": models.SrcPackage{
					Name:        "java-1.8.0-amazon-corretto",
					Version:     "1:1.8.0_432.b06-1.amzn2",
					Arch:        "src",
					BinaryNames: []string{"java-1.8.0-amazon-corretto"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhatBase{
				base: tt.fields.base,
				sudo: tt.fields.sudo,
			}
			gotbps, gotsps, err := o.parseInstalledPackages(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseInstalledPackages() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotbps, tt.wantbps) {
				t.Errorf("redhatBase.parseInstalledPackages() gotbps = %v, wantbps %v", gotbps, tt.wantbps)
			}
			if !reflect.DeepEqual(gotsps, tt.wantsps) {
				t.Errorf("redhatBase.parseInstalledPackages() gotsps = %v, wantsps %v", gotsps, tt.wantsps)
			}
		})
	}
}

func Test_redhatBase_parseInstalledPackagesLine(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name    string
		args    args
		wantbp  *models.Package
		wantsp  *models.SrcPackage
		wantErr bool
	}{
		{
			name: "old: package 1",
			args: args{line: "gpg-pubkey (none) f5282ee4 58ac92a3 (none) (none)"},
			wantbp: &models.Package{
				Name:    "gpg-pubkey",
				Version: "f5282ee4",
				Release: "58ac92a3",
				Arch:    "(none)",
			},
			wantsp: nil,
		},
		{
			name: "epoch in source package",
			args: args{line: "bar 1 9 123a ia64 1:bar-9-123a.src.rpm"},
			wantbp: &models.Package{
				Name:    "bar",
				Version: "1:9",
				Release: "123a",
				Arch:    "ia64",
			},
			wantsp: &models.SrcPackage{
				Name:        "bar",
				Version:     "1:9-123a",
				Arch:        "src",
				BinaryNames: []string{"bar"},
			},
		},
		{
			name: "new: package 1",
			args: args{line: "gpg-pubkey 0 f5282ee4 58ac92a3 (none) (none)"},
			wantbp: &models.Package{
				Name:    "gpg-pubkey",
				Version: "f5282ee4",
				Release: "58ac92a3",
				Arch:    "(none)",
			},
			wantsp: nil,
		},
		{
			name: "new: package 2",
			args: args{line: "openssl-libs 1 1.1.0h 3.fc27 x86_64 openssl-1.1.0h-3.fc27.src.rpm"},
			wantbp: &models.Package{
				Name:    "openssl-libs",
				Version: "1:1.1.0h",
				Release: "3.fc27",
				Arch:    "x86_64",
			},
			wantsp: &models.SrcPackage{
				Name:        "openssl",
				Version:     "1:1.1.0h-3.fc27",
				Arch:        "src",
				BinaryNames: []string{"openssl-libs"},
			},
		},
		{
			name: "modularity: package 1",
			args: args{line: "dnf 0 4.14.0 1.fc35 noarch dnf-4.14.0-1.fc35.src.rpm (none)"},
			wantbp: &models.Package{
				Name:    "dnf",
				Version: "4.14.0",
				Release: "1.fc35",
				Arch:    "noarch",
			},
			wantsp: &models.SrcPackage{
				Name:        "dnf",
				Version:     "4.14.0-1.fc35",
				Arch:        "src",
				BinaryNames: []string{"dnf"},
			},
		},
		{
			name: "modularity: package 2",
			args: args{line: "community-mysql 0 8.0.31 1.module_f35+15642+4eed9dbd x86_64 community-mysql-8.0.31-1.module_f35+15642+4eed9dbd.src.rpm mysql:8.0:3520221024193033:f27b74a8"},
			wantbp: &models.Package{
				Name:            "community-mysql",
				Version:         "8.0.31",
				Release:         "1.module_f35+15642+4eed9dbd",
				Arch:            "x86_64",
				ModularityLabel: "mysql:8.0:3520221024193033:f27b74a8",
			},
			wantsp: &models.SrcPackage{
				Name:        "community-mysql",
				Version:     "8.0.31-1.module_f35+15642+4eed9dbd",
				Arch:        "src",
				BinaryNames: []string{"community-mysql"},
			},
		},
		{
			name: "not standard rpm style source package",
			args: args{line: "elasticsearch 0 8.17.0 1 x86_64 elasticsearch-8.17.0-1-src.rpm (none)"},
			wantbp: &models.Package{
				Name:    "elasticsearch",
				Version: "8.17.0",
				Release: "1",
				Arch:    "x86_64",
			},
			wantsp: &models.SrcPackage{
				Name:        "elasticsearch",
				Version:     "8.17.0-1",
				Arch:        "src",
				BinaryNames: []string{"elasticsearch"},
			},
		},
		{
			name: "not standard rpm style source package 2",
			args: args{line: "package 0 0 1 x86_64 package-0-1-src.rpm (none)"},
			wantbp: &models.Package{
				Name:    "package",
				Version: "0",
				Release: "1",
				Arch:    "x86_64",
			},
			wantsp: &models.SrcPackage{
				Name:        "package",
				Version:     "0-1",
				Arch:        "src",
				BinaryNames: []string{"package"},
			},
		},
		{
			name: "not standard rpm style source package 3",
			args: args{line: "package 0 0 0.1 x86_64 package-0-0.1-src.rpm (none)"},
			wantbp: &models.Package{
				Name:    "package",
				Version: "0",
				Release: "0.1",
				Arch:    "x86_64",
			},
			wantsp: &models.SrcPackage{
				Name:        "package",
				Version:     "0-0.1",
				Arch:        "src",
				BinaryNames: []string{"package"},
			},
		},
		{
			name: "release is empty",
			args: args{line: "package 0 0  x86_64 package-0-.src.rpm (none)"},
			wantbp: &models.Package{
				Name:    "package",
				Version: "0",
				Release: "",
				Arch:    "x86_64",
			},
			wantsp: &models.SrcPackage{
				Name:        "package",
				Version:     "0",
				Arch:        "src",
				BinaryNames: []string{"package"},
			},
		},
		{
			name: "release is empty 2",
			args: args{line: "package 0 0  x86_64 package-0--src.rpm (none)"},
			wantbp: &models.Package{
				Name:    "package",
				Version: "0",
				Release: "",
				Arch:    "x86_64",
			},
			wantsp: &models.SrcPackage{
				Name:        "package",
				Version:     "0",
				Arch:        "src",
				BinaryNames: []string{"package"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotbp, gotsp, err := (&redhatBase{}).parseInstalledPackagesLine(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseInstalledPackagesLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotbp, tt.wantbp) {
				t.Errorf("redhatBase.parseInstalledPackagesLine() gotbp = %v, wantbp %v", gotbp, tt.wantbp)
			}
			if !reflect.DeepEqual(gotsp, tt.wantsp) {
				t.Errorf("redhatBase.parseInstalledPackagesLine() gotsp = %v, wantsp %v", gotsp, tt.wantsp)
			}
		})
	}
}

func Test_redhatBase_parseInstalledPackagesLineFromRepoquery(t *testing.T) {
	type args struct {
		line string
	}
	tests := []struct {
		name    string
		args    args
		wantbp  *models.Package
		wantsp  *models.SrcPackage
		wantErr bool
	}{
		{
			name: "default install",
			args: args{line: "zlib 0 1.2.7 19.amzn2.0.3 x86_64 zlib-1.2.7-19.amzn2.0.3.src.rpm installed"},
			wantbp: &models.Package{
				Name:       "zlib",
				Version:    "1.2.7",
				Release:    "19.amzn2.0.3",
				Arch:       "x86_64",
				Repository: "amzn2-core",
			},
			wantsp: &models.SrcPackage{
				Name:        "zlib",
				Version:     "1.2.7-19.amzn2.0.3",
				Arch:        "src",
				BinaryNames: []string{"zlib"},
			},
		},
		{
			name: "manual install",
			args: args{line: "yum-utils 0 1.1.31 46.amzn2.0.1 noarch yum-utils-1.1.31-46.amzn2.0.1.src.rpm @amzn2-core"},
			wantbp: &models.Package{
				Name:       "yum-utils",
				Version:    "1.1.31",
				Release:    "46.amzn2.0.1",
				Arch:       "noarch",
				Repository: "amzn2-core",
			},
			wantsp: &models.SrcPackage{
				Name:        "yum-utils",
				Version:     "1.1.31-46.amzn2.0.1",
				Arch:        "src",
				BinaryNames: []string{"yum-utils"},
			},
		},
		{
			name: "extra repository",
			args: args{line: "java-1.8.0-amazon-corretto 1 1.8.0_432.b06 1.amzn2 x86_64 java-1.8.0-amazon-corretto-1.8.0_432.b06-1.amzn2.src.rpm @amzn2extra-corretto8"},
			wantbp: &models.Package{
				Name:       "java-1.8.0-amazon-corretto",
				Version:    "1:1.8.0_432.b06",
				Release:    "1.amzn2",
				Arch:       "x86_64",
				Repository: "amzn2extra-corretto8",
			},
			wantsp: &models.SrcPackage{
				Name:        "java-1.8.0-amazon-corretto",
				Version:     "1:1.8.0_432.b06-1.amzn2",
				Arch:        "src",
				BinaryNames: []string{"java-1.8.0-amazon-corretto"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotbp, gotsp, err := (&redhatBase{}).parseInstalledPackagesLineFromRepoquery(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseInstalledPackagesLineFromRepoquery() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotbp, tt.wantbp) {
				t.Errorf("redhatBase.parseInstalledPackagesLineFromRepoquery() gotbp = %v, wantbp %v", gotbp, tt.wantbp)
			}
			if !reflect.DeepEqual(gotsp, tt.wantsp) {
				t.Errorf("redhatBase.parseInstalledPackagesLineFromRepoquery() gotsp = %v, wantsp %v", gotsp, tt.wantsp)
			}
		})
	}
}

func Test_redhatBase_parseUpdatablePacksLine(t *testing.T) {
	type fields struct {
		base base
		sudo rootPriv
	}
	type args struct {
		line string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *models.Package
		wantErr bool
	}{
		{
			name: `centos 7.0: "zlib" "0" "1.2.7" "17.el7" "rhui-REGION-rhel-server-releases"`,
			fields: fields{
				base: base{
					Distro: config.Distro{
						Family:  constant.CentOS,
						Release: "7.0",
					},
				},
			},
			args: args{
				line: `"zlib" "0" "1.2.7" "17.el7" "rhui-REGION-rhel-server-releases"`,
			},
			want: &models.Package{
				Name:       "zlib",
				NewVersion: "1.2.7",
				NewRelease: "17.el7",
				Repository: "rhui-REGION-rhel-server-releases",
			},
		},
		{
			name: `centos 7.0: "shadow-utils" "2" "4.1.5.1 24.el7" "rhui-REGION-rhel-server-releases"`,
			fields: fields{
				base: base{
					Distro: config.Distro{
						Family:  constant.CentOS,
						Release: "7.0",
					},
				},
			},
			args: args{
				line: `"shadow-utils" "2" "4.1.5.1" "24.el7" "rhui-REGION-rhel-server-releases"`,
			},
			want: &models.Package{
				Name:       "shadow-utils",
				NewVersion: "2:4.1.5.1",
				NewRelease: "24.el7",
				Repository: "rhui-REGION-rhel-server-releases",
			},
		},
		{
			name: `amazon 2023: Is this ok [y/N]: `,
			fields: fields{
				base: base{
					Distro: config.Distro{
						Family:  constant.Amazon,
						Release: "2023.7.20250512",
					},
				},
			},
			args: args{
				line: `Is this ok [y/N]: `,
			},
			want: nil,
		},
		{
			name: `amazon 2023: Is this ok [y/N]: "dnf" "0" "4.14.0" "1.amzn2023.0.6" "amazonlinux"`,
			fields: fields{
				base: base{
					Distro: config.Distro{
						Family:  constant.Amazon,
						Release: "2023.7.20250512",
					},
				},
			},
			args: args{
				line: `Is this ok [y/N]: "dnf" "0" "4.14.0" "1.amzn2023.0.6" "amazonlinux"`,
			},
			want: &models.Package{
				Name:       "dnf",
				NewVersion: "4.14.0",
				NewRelease: "1.amzn2023.0.6",
				Repository: "amazonlinux",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhatBase{
				base: tt.fields.base,
				sudo: tt.fields.sudo,
			}
			got, err := o.parseUpdatablePacksLine(tt.args.line)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseUpdatablePacksLine() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhatBase.parseUpdatablePacksLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_redhatBase_parseUpdatablePacksLines(t *testing.T) {
	type fields struct {
		base base
		sudo rootPriv
	}
	type args struct {
		stdout string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    models.Packages
		wantErr bool
	}{
		{
			name: "centos",
			fields: fields{
				base: base{
					Distro: config.Distro{
						Family: constant.CentOS,
					},
					osPackages: osPackages{
						Packages: models.Packages{
							"audit-libs":         {Name: "audit-libs"},
							"bash":               {Name: "bash"},
							"python-libs":        {Name: "python-libs"},
							"python-ordereddict": {Name: "python-ordereddict"},
							"bind-utils":         {Name: "bind-utils"},
							"pytalloc":           {Name: "pytalloc"},
						},
					},
				},
			},
			args: args{
				stdout: `"audit-libs" "0" "2.3.7" "5.el6" "base"
"bash" "0" "4.1.2" "33.el6_7.1" "updates"
"python-libs" "0" "2.6.6" "64.el6" "rhui-REGION-rhel-server-releases"
"python-ordereddict" "0" "1.1" "3.el6ev" "installed"
"bind-utils" "30" "9.3.6" "25.P1.el5_11.8" "updates"
"pytalloc" "0" "2.0.7" "2.el6" "@CentOS 6.5/6.5"`},
			want: models.Packages{
				"audit-libs": {
					Name:       "audit-libs",
					NewVersion: "2.3.7",
					NewRelease: "5.el6",
					Repository: "base",
				},
				"bash": {
					Name:       "bash",
					NewVersion: "4.1.2",
					NewRelease: "33.el6_7.1",
					Repository: "updates",
				},
				"python-libs": {
					Name:       "python-libs",
					NewVersion: "2.6.6",
					NewRelease: "64.el6",
					Repository: "rhui-REGION-rhel-server-releases",
				},
				"python-ordereddict": {
					Name:       "python-ordereddict",
					NewVersion: "1.1",
					NewRelease: "3.el6ev",
					Repository: "installed",
				},
				"bind-utils": {
					Name:       "bind-utils",
					NewVersion: "30:9.3.6",
					NewRelease: "25.P1.el5_11.8",
					Repository: "updates",
				},
				"pytalloc": {
					Name:       "pytalloc",
					NewVersion: "2.0.7",
					NewRelease: "2.el6",
					Repository: "@CentOS 6.5/6.5",
				},
			},
		},
		{
			name: "amazon",
			fields: fields{
				base: base{
					Distro: config.Distro{
						Family: constant.Amazon,
					},
					osPackages: osPackages{
						Packages: models.Packages{
							"bind-libs":           {Name: "bind-libs"},
							"java-1.7.0-openjdk":  {Name: "java-1.7.0-openjdk"},
							"if-not-architecture": {Name: "if-not-architecture"},
						},
					},
				},
			},
			args: args{
				stdout: `"bind-libs" "32" "9.8.2" "0.37.rc1.45.amzn1" "amzn-main"
"java-1.7.0-openjdk" "0" "1.7.0.95" "2.6.4.0.65.amzn1" "amzn-main"
"if-not-architecture" "0" "100" "200" "amzn-main"`,
			},
			want: models.Packages{
				"bind-libs": {
					Name:       "bind-libs",
					NewVersion: "32:9.8.2",
					NewRelease: "0.37.rc1.45.amzn1",
					Repository: "amzn-main",
				},
				"java-1.7.0-openjdk": {
					Name:       "java-1.7.0-openjdk",
					NewVersion: "1.7.0.95",
					NewRelease: "2.6.4.0.65.amzn1",
					Repository: "amzn-main",
				},
				"if-not-architecture": {
					Name:       "if-not-architecture",
					NewVersion: "100",
					NewRelease: "200",
					Repository: "amzn-main",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &redhatBase{
				base: tt.fields.base,
				sudo: tt.fields.sudo,
			}
			got, err := o.parseUpdatablePacksLines(tt.args.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("redhatBase.parseUpdatablePacksLines() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redhatBase.parseUpdatablePacksLines() = %v, want %v", got, tt.want)
			}
		})
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
30170 : 
437 : /usr/sbin/NetworkManager --no-daemon`,
			[]models.NeedRestartProcess{
				{
					PID:     "30170",
					Path:    "",
					HasInit: true,
				},
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
			args:   args{line: "Percona-Server-shared-56 1 5.6.19 rel67.0.el6 x86_64 Percona-SQL-56-5.6.19-rel67.0.el6.src.rpm"},
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
				fn: func(_ string) execResult {
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
				fn: func(_ string) execResult {
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
				fn: func(_ string) execResult {
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
				fn: func(_ string) execResult {
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
