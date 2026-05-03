//go:build !scanner

package detector

import (
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_canonicalMavenPURL(t *testing.T) {
	tests := []struct {
		name string
		pkg  ftypes.Package
		want string
	}{
		{
			name: "groupId:artifactId resolves to namespace/name purl",
			pkg: ftypes.Package{
				Name:    "org.apache.logging.log4j:log4j-core",
				Version: "2.14.1",
			},
			want: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		},
		{
			name: "Trivy Java DB result with multi-segment groupId",
			pkg: ftypes.Package{
				Name:    "org.springframework.boot:spring-boot-starter-jdbc",
				Version: "2.5.0",
			},
			want: "pkg:maven/org.springframework.boot/spring-boot-starter-jdbc@2.5.0",
		},
		{
			name: "groupId == artifactId (legitimate Maven 1 coords)",
			pkg: ftypes.Package{
				Name:    "antlr:antlr",
				Version: "2.7.7",
			},
			want: "pkg:maven/antlr/antlr@2.7.7",
		},
		{
			name: "version string with `+` build-metadata is purl-encoded",
			pkg: ftypes.Package{
				Name:    "com.example:example",
				Version: "1.0+build.1",
			},
			want: "pkg:maven/com.example/example@1.0%2Bbuild.1",
		},
		// Defensive guards: caller must keep its existing PURL when input
		// does not look like a canonical "groupId:artifactId" pair.
		{
			name: "Name with no colon (groupId-less Trivy fallback) returns empty",
			pkg: ftypes.Package{
				Name:    "log4j-core",
				Version: "2.14.1",
			},
			want: "",
		},
		{
			name: "Name with empty groupId returns empty",
			pkg: ftypes.Package{
				Name:    ":log4j-core",
				Version: "2.14.1",
			},
			want: "",
		},
		{
			name: "Name with empty artifactId returns empty",
			pkg: ftypes.Package{
				Name:    "org.apache.logging.log4j:",
				Version: "2.14.1",
			},
			want: "",
		},
		{
			name: "empty Name returns empty",
			pkg: ftypes.Package{
				Name:    "",
				Version: "2.14.1",
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalMavenPURL(tt.pkg)
			if got != tt.want {
				t.Errorf("canonicalMavenPURL(%+v) = %q, want %q", tt.pkg, got, tt.want)
			}
		})
	}
}
