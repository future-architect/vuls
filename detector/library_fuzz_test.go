//go:build !scanner

package detector

import (
	"strings"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// FuzzCanonicalMavenPURL drives random "groupId:artifactId" / version pairs
// through canonicalMavenPURL. It enforces:
//   - the function never panics,
//   - the empty-input guard ("" group, "" artifact, no ':') always returns "",
//   - any non-empty result is a syntactically plausible Maven purl.
func FuzzCanonicalMavenPURL(f *testing.F) {
	seeds := []struct{ name, version string }{
		{"org.apache.logging.log4j:log4j-core", "2.14.1"},
		{"org.springframework.boot:spring-boot-starter-jdbc", "2.5.0"},
		{"antlr:antlr", "2.7.7"},
		{"com.example:example", "1.0+build.1"},
		{"log4j-core", "2.14.1"},
		{":log4j-core", "2.14.1"},
		{"org.apache.logging.log4j:", "2.14.1"},
		{"", "2.14.1"},
		{"a:b", ""},
		{"a:b:c", "1"},
		{"a/b:c", "1.0"},
		{"a:b@c", "1.0"},
	}
	for _, s := range seeds {
		f.Add(s.name, s.version)
	}

	f.Fuzz(func(t *testing.T, name, version string) {
		got := canonicalMavenPURL(ftypes.Package{Name: name, Version: version})

		group, artifact, hasColon := strings.Cut(name, ":")
		if !hasColon || group == "" || artifact == "" {
			if got != "" {
				t.Fatalf("expected empty for non-canonical name %q, got %q", name, got)
			}
			return
		}

		if got == "" {
			// purl.New rejected the input — acceptable, no further checks.
			return
		}
		if !strings.HasPrefix(got, "pkg:maven/") {
			t.Fatalf("canonicalMavenPURL(%q,%q) = %q: missing pkg:maven/ prefix", name, version, got)
		}
	})
}
