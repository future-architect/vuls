package pkg_test

import (
	"testing"

	trivydbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/future-architect/vuls/contrib/trivy/pkg"
	"github.com/future-architect/vuls/models"
)

func Test_getLockfilePath(t *testing.T) {
	type args struct {
		scanmode     ftypes.ArtifactType
		artifactName string
		libType      ftypes.LangType
		target       string
		libFilepath  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "image lockfiles:latest cargo lockfiles/Cargo.lock (empty)",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.Cargo,
				target:       "lockfiles/Cargo.lock",
				libFilepath:  "",
			},
			want: "/lockfiles/Cargo.lock",
		},
		{
			name: "rootfs 4a14f0cecb17 cargo lockfiles/Cargo.lock (empty)",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.Cargo,
				target:       "lockfiles/Cargo.lock",
				libFilepath:  "",
			},
			want: "lockfiles/Cargo.lock",
		},
		{
			name: "filesystem lockfiles/Cargo.lock cargo Cargo.lock (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/Cargo.lock",
				libType:      ftypes.Cargo,
				target:       "Cargo.lock",
				libFilepath:  "",
			},
			want: "lockfiles/Cargo.lock",
		},
		{
			name: "filesystem lockfiles cargo Cargo.lock (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.Cargo,
				target:       "Cargo.lock",
				libFilepath:  "",
			},
			want: "lockfiles/Cargo.lock",
		},
		{
			name: "repository lockfiles/Cargo.lock cargo Cargo.lock (empty)",
			args: args{
				scanmode:     ftypes.TypeRepository,
				artifactName: "lockfiles/Cargo.lock",
				libType:      ftypes.Cargo,
				target:       "Cargo.lock",
				libFilepath:  "",
			},
			want: "lockfiles/Cargo.lock",
		},
		{
			name: "repository lockfiles cargo Cargo.lock (empty)",
			args: args{
				scanmode:     ftypes.TypeRepository,
				artifactName: "lockfiles",
				libType:      ftypes.Cargo,
				target:       "Cargo.lock",
				libFilepath:  "",
			},
			want: "lockfiles/Cargo.lock",
		},
		{
			name: "image lockfiles:latest node-pkg Node.js (empty)",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "",
			},
			want: "/Node.js",
		},
		{
			name: "image lockfiles:latest node-pkg Node.js lockfiles/package.json",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "lockfiles/package.json",
			},
			want: "/lockfiles/package.json",
		},
		{
			name: "rootfs 4a14f0cecb17 node-pkg Node.js (empty)",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "",
			},
			want: "Node.js",
		},
		{
			name: "rootfs 4a14f0cecb17 node-pkg Node.js lockfiles/package.json",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "lockfiles/package.json",
			},
			want: "lockfiles/package.json",
		},
		{
			name: "filesystem lockfiles/package.json node-pkg Node.js (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/package.json",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "",
			},
			want: "lockfiles/package.json/Node.js",
		},
		{
			name: "filesystem lockfiles/package.json node-pkg Node.js package.json",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/package.json",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "package.json",
			},
			want: "lockfiles/package.json",
		},
		{
			name: "filesystem lockfiles node-pkg Node.js (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "",
			},
			want: "lockfiles/Node.js",
		},
		{
			name: "filesystem lockfiles node-pkg Node.js package.json",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.NodePkg,
				target:       "Node.js",
				libFilepath:  "package.json",
			},
			want: "lockfiles/package.json",
		},
		{
			name: "image lockfiles:latest gemspec Ruby (empty)",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "",
			},
			want: "/Ruby",
		},
		{
			name: "image lockfiles:latest gemspec Ruby lockfiles/ruby/specifications/rake.gemspec",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "lockfiles/ruby/specifications/rake.gemspec",
			},
			want: "/lockfiles/ruby/specifications/rake.gemspec",
		},
		{
			name: "rootfs 4a14f0cecb17 gemspec Ruby (empty)",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "",
			},
			want: "Ruby",
		},
		{
			name: "rootfs 4a14f0cecb17 gemspec Ruby lockfiles/ruby/specifications/rake.gemspec",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "lockfiles/ruby/specifications/rake.gemspec",
			},
			want: "lockfiles/ruby/specifications/rake.gemspec",
		},
		{
			name: "filesystem lockfiles/ruby/specifications/rake.gemspec gemspec Ruby (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/ruby/specifications/rake.gemspec",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "",
			},
			want: "lockfiles/ruby/specifications/rake.gemspec/Ruby",
		},
		{
			name: "filesystem lockfiles/ruby/specifications/rake.gemspec gemspec Ruby rake.gemspec",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/ruby/specifications/rake.gemspec",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "rake.gemspec",
			},
			want: "lockfiles/ruby/specifications/rake.gemspec",
		},
		{
			name: "filesystem lockfiles gemspec Ruby (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "",
			},
			want: "lockfiles/Ruby",
		},
		{
			name: "filesystem lockfiles gemspec Ruby ruby/specifications/rake.gemspec",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.GemSpec,
				target:       "Ruby",
				libFilepath:  "ruby/specifications/rake.gemspec",
			},
			want: "lockfiles/ruby/specifications/rake.gemspec",
		},
		{
			name: "image lockfiles:latest python-pkg Python (empty)",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "",
			},
			want: "/Python",
		},
		{
			name: "image lockfiles:latest python-pkg Python lockfiles/packaging-25.0.dist-info/METADATA",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "lockfiles/packaging-25.0.dist-info/METADATA",
			},
			want: "/lockfiles/packaging-25.0.dist-info/METADATA",
		},
		{
			name: "rootfs 4a14f0cecb17 python-pkg Python (empty)",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "",
			},
			want: "Python",
		},
		{
			name: "rootfs 4a14f0cecb17 python-pkg Python lockfiles/packaging-25.0.dist-info/METADATA",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "lockfiles/packaging-25.0.dist-info/METADATA",
			},
			want: "lockfiles/packaging-25.0.dist-info/METADATA",
		},
		{
			name: "filesystem lockfiles/packaging-25.0.dist-info python-pkg Python (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/packaging-25.0.dist-info",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "",
			},
			want: "lockfiles/packaging-25.0.dist-info/Python",
		},
		{
			name: "filesystem lockfiles/packaging-25.0.dist-info python-pkg Python METADATA",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/packaging-25.0.dist-info",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "METADATA",
			},
			want: "lockfiles/packaging-25.0.dist-info/METADATA",
		},
		{
			name: "filesystem lockfiles python-pkg Python (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "",
			},
			want: "lockfiles/Python",
		},
		{
			name: "filesystem lockfiles python-pkg Python packaging-25.0.dist-info/METADATA",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.PythonPkg,
				target:       "Python",
				libFilepath:  "packaging-25.0.dist-info/METADATA",
			},
			want: "lockfiles/packaging-25.0.dist-info/METADATA",
		},
		{
			name: "image lockfiles:latest jar Java (empty)",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "",
			},
			want: "/Java",
		},
		{
			name: "image lockfiles:latest jar Java lockfiles/log4j-core-2.13.0.jar",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "lockfiles/log4j-core-2.13.0.jar",
			},
			want: "/lockfiles/log4j-core-2.13.0.jar",
		},
		{
			name: "image lockfiles:latest jar Java lockfiles/juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			args: args{
				scanmode:     ftypes.TypeContainerImage,
				artifactName: "lockfiles:latest",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "lockfiles/juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			},
			want: "/lockfiles/juddiv3-war-3.3.5.war",
		},
		{
			name: "rootfs 4a14f0cecb17 jar Java (empty)",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "",
			},
			want: "Java",
		},
		{
			name: "rootfs 4a14f0cecb17 jar Java lockfiles/log4j-core-2.13.0.jar",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "lockfiles/log4j-core-2.13.0.jar",
			},
			want: "lockfiles/log4j-core-2.13.0.jar",
		},
		{
			name: "rootfs 4a14f0cecb17 jar Java lockfiles/juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			args: args{
				scanmode:     "rootfs",
				artifactName: "4a14f0cecb17",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "lockfiles/juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			},
			want: "lockfiles/juddiv3-war-3.3.5.war",
		},
		{
			name: "filesystem lockfiles/log4j-core-2.13.0.jar jar Java (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/log4j-core-2.13.0.jar",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "",
			},
			want: "lockfiles/log4j-core-2.13.0.jar/Java",
		},
		{
			name: "filesystem lockfiles/log4j-core-2.13.0.jar jar Java log4j-core-2.13.0.jar",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/log4j-core-2.13.0.jar",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "log4j-core-2.13.0.jar",
			},
			want: "lockfiles/log4j-core-2.13.0.jar",
		},
		{
			name: "filesystem lockfiles/juddiv3-war-3.3.5.war jar Java juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles/juddiv3-war-3.3.5.war",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			},
			want: "lockfiles/juddiv3-war-3.3.5.war",
		},
		{
			name: "filesystem lockfiles jar Java (empty)",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "",
			},
			want: "lockfiles/Java",
		},
		{
			name: "filesystem lockfiles jar Java log4j-core-2.13.0.jar",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "log4j-core-2.13.0.jar",
			},
			want: "lockfiles/log4j-core-2.13.0.jar",
		},
		{
			name: "filesystem lockfiles jar Java juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			args: args{
				scanmode:     ftypes.TypeFilesystem,
				artifactName: "lockfiles",
				libType:      ftypes.Jar,
				target:       "Java",
				libFilepath:  "juddiv3-war-3.3.5.war/WEB-INF/lib/log4j-1.2.17.jar",
			},
			want: "lockfiles/juddiv3-war-3.3.5.war",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pkg.GetLockfilePath(tt.args.scanmode, tt.args.artifactName, tt.args.libType, tt.args.target, tt.args.libFilepath); got != tt.want {
				t.Errorf("getLockfilePath() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConvert(t *testing.T) {
	type args struct {
		results      types.Results
		artifactType ftypes.ArtifactType
		artifactName string
	}
	tests := []struct {
		name string
		args args
		want *models.ScanResult
	}{
		{
			name: "no duplicate, single source",
			args: args{
				results: types.Results{
					{
						Target: "debian 13.3",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Debian,
						Packages: []ftypes.Package{
							{
								Name:       "libssl3t64",
								Version:    "3.5.5",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
						},
					},
				},
				artifactType: ftypes.TypeContainerImage,
				artifactName: "test:latest",
			},
			want: &models.ScanResult{
				JSONVersion:     models.JSONVersion,
				ScannedCves:     models.VulnInfos{},
				LibraryScanners: models.LibraryScanners{},
				Packages: models.Packages{
					"libssl3t64": {
						Name:    "libssl3t64",
						Version: "3.5.5-1~deb13u1",
						Arch:    "amd64",
					},
				},
				SrcPackages: models.SrcPackages{
					"openssl": {
						Name:        "openssl",
						Version:     "3.5.5-1~deb13u1",
						BinaryNames: []string{"libssl3t64"},
					},
				},
			},
		},
		{
			// Duplicate packages from status + status.d/: newer version wins via dpkg comparison.
			name: "duplicate packages, newer wins",
			args: args{
				results: types.Results{
					{
						Target: "debian 13.3",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Debian,
						Packages: []ftypes.Package{
							{
								Name:       "libssl3t64",
								Version:    "3.5.4",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.4",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
							{
								Name:       "libssl3t64",
								Version:    "3.5.5",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
						},
					},
				},
				artifactType: ftypes.TypeContainerImage,
				artifactName: "test:latest",
			},
			want: &models.ScanResult{
				JSONVersion:     models.JSONVersion,
				ScannedCves:     models.VulnInfos{},
				LibraryScanners: models.LibraryScanners{},
				Warnings: []string{
					"Duplicate OS package detected: libssl3t64 (3.5.4-1~deb13u1, 3.5.5-1~deb13u1). The newest version is kept, but false-positive CVEs may remain.",
				},
				Packages: models.Packages{
					"libssl3t64": {
						Name:    "libssl3t64",
						Version: "3.5.5-1~deb13u1",
						Arch:    "amd64",
					},
				},
				SrcPackages: models.SrcPackages{
					"openssl": {
						Name:        "openssl",
						Version:     "3.5.5-1~deb13u1",
						BinaryNames: []string{"libssl3t64"},
					},
				},
			},
		},
		{
			// Reverse order: newer version still wins regardless of input order.
			name: "duplicate packages reverse order, newer wins",
			args: args{
				results: types.Results{
					{
						Target: "debian 13.3",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Debian,
						Packages: []ftypes.Package{
							{
								Name:       "libssl3t64",
								Version:    "3.5.5",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
							{
								Name:       "libssl3t64",
								Version:    "3.5.4",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.4",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
						},
					},
				},
				artifactType: ftypes.TypeContainerImage,
				artifactName: "test:latest",
			},
			want: &models.ScanResult{
				JSONVersion:     models.JSONVersion,
				ScannedCves:     models.VulnInfos{},
				LibraryScanners: models.LibraryScanners{},
				Warnings: []string{
					"Duplicate OS package detected: libssl3t64 (3.5.4-1~deb13u1, 3.5.5-1~deb13u1). The newest version is kept, but false-positive CVEs may remain.",
				},
				Packages: models.Packages{
					"libssl3t64": {
						Name:    "libssl3t64",
						Version: "3.5.5-1~deb13u1",
						Arch:    "amd64",
					},
				},
				SrcPackages: models.SrcPackages{
					"openssl": {
						Name:        "openssl",
						Version:     "3.5.5-1~deb13u1",
						BinaryNames: []string{"libssl3t64"},
					},
				},
			},
		},
		{
			// BinaryNames are accumulated across all duplicates.
			name: "multiple binary packages with duplicates",
			args: args{
				results: types.Results{
					{
						Target: "debian 13.3",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Debian,
						Packages: []ftypes.Package{
							{
								Name:       "libssl3t64",
								Version:    "3.5.4",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.4",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
							{
								Name:       "openssl-provider-legacy",
								Version:    "3.5.4",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.4",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
							{
								Name:       "libssl3t64",
								Version:    "3.5.5",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
							{
								Name:       "openssl-provider-legacy",
								Version:    "3.5.5",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
						},
					},
				},
				artifactType: ftypes.TypeContainerImage,
				artifactName: "test:latest",
			},
			want: &models.ScanResult{
				JSONVersion:     models.JSONVersion,
				ScannedCves:     models.VulnInfos{},
				LibraryScanners: models.LibraryScanners{},
				Warnings: []string{
					"Duplicate OS package detected: libssl3t64 (3.5.4-1~deb13u1, 3.5.5-1~deb13u1). The newest version is kept, but false-positive CVEs may remain.",
					"Duplicate OS package detected: openssl-provider-legacy (3.5.4-1~deb13u1, 3.5.5-1~deb13u1). The newest version is kept, but false-positive CVEs may remain.",
				},
				Packages: models.Packages{
					"libssl3t64": {
						Name:    "libssl3t64",
						Version: "3.5.5-1~deb13u1",
						Arch:    "amd64",
					},
					"openssl-provider-legacy": {
						Name:    "openssl-provider-legacy",
						Version: "3.5.5-1~deb13u1",
						Arch:    "amd64",
					},
				},
				SrcPackages: models.SrcPackages{
					"openssl": {
						Name:        "openssl",
						Version:     "3.5.5-1~deb13u1",
						BinaryNames: []string{"libssl3t64", "openssl-provider-legacy"},
					},
				},
			},
		},
		{
			// Non-dpkg OS: duplicates are unrealistic, but verifies the lexicographic fallback path.
			name: "non-dpkg OS, lexicographic comparison (unrealistic)",
			args: args{
				results: types.Results{
					{
						Target: "alpine 3.21",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Alpine,
						Packages: []ftypes.Package{
							{
								Name:       "openssl",
								Version:    "3.5.5",
								Release:    "r0",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "r0",
								Arch:       "x86_64",
							},
							{
								Name:       "openssl",
								Version:    "3.5.4",
								Release:    "r0",
								SrcName:    "openssl",
								SrcVersion: "3.5.4",
								SrcRelease: "r0",
								Arch:       "x86_64",
							},
						},
					},
				},
				artifactType: ftypes.TypeContainerImage,
				artifactName: "test:latest",
			},
			want: &models.ScanResult{
				JSONVersion:     models.JSONVersion,
				ScannedCves:     models.VulnInfos{},
				LibraryScanners: models.LibraryScanners{},
				Warnings: []string{
					"Duplicate OS package detected: openssl (3.5.4-r0, 3.5.5-r0). The newest version is kept, but false-positive CVEs may remain.",
				},
				Packages: models.Packages{
					"openssl": {
						Name:    "openssl",
						Version: "3.5.5-r0",
						Arch:    "x86_64",
					},
				},
				SrcPackages: models.SrcPackages{
					"openssl": {
						Name:        "openssl",
						Version:     "3.5.5-r0",
						BinaryNames: []string{"openssl"},
					},
				},
			},
		},
		{
			// The Vulnerabilities loop writes pkgs entries without Arch.
			// The ClassOSPkg Packages loop must overwrite with same version
			// to add Arch (hence >= not > in compareVersions).
			name: "vuln entry without Arch is augmented by Packages entry",
			args: args{
				results: types.Results{
					{
						Target: "debian 13.3",
						Class:  types.ClassOSPkg,
						Type:   ftypes.Debian,
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2025-99999",
								PkgName:          "libssl3t64",
								InstalledVersion: "3.5.5-1~deb13u1",
								Vulnerability: trivydbTypes.Vulnerability{
									VendorSeverity: trivydbTypes.VendorSeverity{
										vulnerability.Debian: trivydbTypes.SeverityLow,
									},
								},
							},
						},
						Packages: []ftypes.Package{
							{
								Name:       "libssl3t64",
								Version:    "3.5.5",
								Release:    "1~deb13u1",
								SrcName:    "openssl",
								SrcVersion: "3.5.5",
								SrcRelease: "1~deb13u1",
								Arch:       "amd64",
							},
						},
					},
				},
				artifactType: ftypes.TypeContainerImage,
				artifactName: "test:latest",
			},
			want: &models.ScanResult{
				JSONVersion: models.JSONVersion,
				ScannedCves: models.VulnInfos{
					"CVE-2025-99999": {
						CveID: "CVE-2025-99999",
						Confidences: models.Confidences{
							{Score: 100, DetectionMethod: models.TrivyMatchStr},
						},
						AffectedPackages: models.PackageFixStatuses{
							{Name: "libssl3t64", NotFixedYet: true, FixState: "Affected"},
						},
						CveContents: models.CveContents{
							"trivy:debian": []models.CveContent{{
								Type:          "trivy:debian",
								CveID:         "CVE-2025-99999",
								Cvss3Severity: "LOW",
							}},
						},
						LibraryFixedIns: models.LibraryFixedIns{},
					},
				},
				LibraryScanners: models.LibraryScanners{},
				Packages: models.Packages{
					"libssl3t64": {
						Name:    "libssl3t64",
						Version: "3.5.5-1~deb13u1",
						Arch:    "amd64",
					},
				},
				SrcPackages: models.SrcPackages{
					"openssl": {
						Name:        "openssl",
						Version:     "3.5.5-1~deb13u1",
						BinaryNames: []string{"libssl3t64"},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pkg.Convert(tt.args.results, tt.args.artifactType, tt.args.artifactName)
			if err != nil {
				t.Fatalf("Convert() error = %v", err)
			}

			if diff := gocmp.Diff(tt.want, got, gocmpopts.IgnoreFields(models.ScanResult{}, "Config")); diff != "" {
				t.Errorf("Convert() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
