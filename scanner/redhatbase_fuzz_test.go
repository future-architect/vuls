package scanner

import (
	"strings"
	"testing"
)

// FuzzParseInstalledPackagesLine drives random whitespace-separated lines
// through (redhatBase).parseInstalledPackagesLine. Invariants:
//   - never panic,
//   - if err == nil, the returned Package is non-nil and Name matches the
//     first whitespace-separated field of the input.
func FuzzParseInstalledPackagesLine(f *testing.F) {
	seeds := []string{
		"gpg-pubkey (none) f5282ee4 58ac92a3 (none) (none)",
		"bar 1 9 123a ia64 1:bar-9-123a.src.rpm",
		"openssl-libs 1 1.1.0h 3.fc27 x86_64 openssl-1.1.0h-3.fc27.src.rpm",
		"dnf 0 4.14.0 1.fc35 noarch dnf-4.14.0-1.fc35.src.rpm (none)",
		"community-mysql 0 8.0.31 1.module_f35+15642+4eed9dbd x86_64 community-mysql-8.0.31-1.module_f35+15642+4eed9dbd.src.rpm mysql:8.0:3520221024193033:f27b74a8",
		"elasticsearch 0 8.17.0 1 x86_64 elasticsearch-8.17.0-1-src.rpm (none)",
		"package 0 0 1 x86_64 package-0-1-src.rpm (none)",
		"package 0 0  x86_64 package-0--src.rpm (none)",
		"a b c d e f",
		"a b c d e f g",
		"",
		"a",
		"a b c d e :",
		"a b c d e -",
		"a b c d e .",
		"a b c d e .rpm",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		o := &redhatBase{}
		bp, _, err := o.parseInstalledPackagesLine(line)
		if err != nil {
			return
		}
		if bp == nil {
			t.Fatalf("parseInstalledPackagesLine(%q): nil err but Package is nil", line)
		}
		fields := strings.Split(line, " ")
		if bp.Name != fields[0] {
			t.Fatalf("parseInstalledPackagesLine(%q): Name=%q, want %q", line, bp.Name, fields[0])
		}
	})
}

// FuzzSplitFileName drives random RPM-like file names through splitFileName.
// Invariants:
//   - the function never panics (Go fuzzing detects this automatically),
//   - if err == nil, all returned substrings come from the input (no
//     character invention),
//   - if err == nil, the package name is non-empty (an empty Name silently
//     emitted would corrupt the resulting models.Package downstream).
//
// The doc comment explicitly accepts cases like "qux-0--i386" where rel
// ends up empty, so empty rel/epoch are tolerated.
func FuzzSplitFileName(f *testing.F) {
	seeds := []string{
		"foo-1.0-1.i386.rpm",
		"1:bar-9-123a.ia64.rpm",
		"baz-0-1-i386",
		"qux-0--i386",
		"Percona-Server-shared-56-1:5.6.19-rel67.0.el6.x86_64",
		"kernel-3.10.0-1160.el7.x86_64.rpm",
		"glibc-2.17-326.el7_9.x86_64",
		"NetworkManager-1:1.40.16-1.el8.x86_64.rpm",
		"",
		".rpm",
		"a.rpm",
		"a-b.rpm",
		"a-b-c.rpm",
		"a-b-c.d.rpm",
		":",
		"-",
		"-.",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, filename string) {
		name, ver, rel, epoch, arch, err := splitFileName(filename)
		if err != nil {
			return
		}

		basename := strings.TrimSuffix(filename, ".rpm")
		for _, p := range []struct {
			label string
			value string
		}{
			{"name", name},
			{"ver", ver},
			{"rel", rel},
			{"epoch", epoch},
			{"arch", arch},
		} {
			if p.value != "" && !strings.Contains(basename, p.value) {
				t.Fatalf("splitFileName(%q): %s=%q not found in basename %q",
					filename, p.label, p.value, basename)
			}
		}

		if name == "" {
			t.Fatalf("splitFileName(%q) returned nil err but Name is empty: ver=%q rel=%q epoch=%q arch=%q",
				filename, ver, rel, epoch, arch)
		}
	})
}
