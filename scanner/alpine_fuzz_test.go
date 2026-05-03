package scanner

import (
	"testing"

	"github.com/future-architect/vuls/config"
)

// FuzzParseApkIndex drives random APKINDEX-like blocks through
// (alpine).parseApkIndex. Invariants:
//   - never panic,
//   - if err == nil, every entry in the returned map has matching key/Name
//     and a non-empty Version.
func FuzzParseApkIndex(f *testing.F) {
	seeds := []string{
		"P:alpine-baselayout\nV:3.6.5-r0\nA:x86_64\no:alpine-baselayout\n",
		"P:foo\nV:1.0\nA:noarch\n\nP:bar\nV:2.0\no:foo\n",
		"P:foo\nV:1.0\n",
		"",
		"\n",
		"\n\n",
		"P:\nV:\n",
		"P:foo\n",
		"V:1.0\n",
		"only-no-colon-line\n",
		":\n",
		"P:a\nV:b\nP:c\nV:d\n",
		"P:a\nV:b\n\nP:c\nV:d\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, stdout string) {
		o := newAlpine(config.ServerInfo{})
		bins, srcs, err := o.parseApkIndex(stdout)
		if err != nil {
			return
		}
		for key, pkg := range bins {
			if pkg.Name != key {
				t.Fatalf("parseApkIndex(%q): bin map key %q != Name %q", stdout, key, pkg.Name)
			}
			if pkg.Version == "" {
				t.Fatalf("parseApkIndex(%q): bin %q has empty Version", stdout, key)
			}
		}
		for key, sp := range srcs {
			if sp.Name != key {
				t.Fatalf("parseApkIndex(%q): src map key %q != Name %q", stdout, key, sp.Name)
			}
			if sp.Version == "" {
				t.Fatalf("parseApkIndex(%q): src %q has empty Version", stdout, key)
			}
		}
	})
}
