package pkg_test

import (
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/future-architect/vuls/contrib/trivy/pkg"
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
