package scanner

import (
	"strings"
	"testing"
)

// FuzzParseScannedPackagesLine drives random comma-separated lines through
// (debian).parseScannedPackagesLine. Invariants:
//   - never panic,
//   - if err == nil, name is non-empty and matches the first comma-separated
//     field with any ":arch" suffix stripped.
func FuzzParseScannedPackagesLine(f *testing.F) {
	seeds := []string{
		"linux-base,ii ,4.9,linux-base,4.9",
		"linux-libc-dev:amd64,ii ,6.1.90-1,linux,6.1.90-1",
		"linux-image-6.1.0-18-amd64,ii ,6.1.76-1,linux-signed-amd64,6.1.76+1",
		"package,ii , , , ",
		",,,,",
		"a,b,c,d,e",
		"a:x,b,c,d,e",
		"a:x:y,b,c,d,e",
		"",
		"only,three,fields",
		"a,b,c,d,e,f",
		"name:arch,status,version,srcname srcver,srcversion",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		o := &debian{}
		name, _, _, _, _, err := o.parseScannedPackagesLine(line)
		if err != nil {
			return
		}

		ss := strings.Split(line, ",")
		expected := ss[0]
		if i := strings.IndexRune(expected, ':'); i >= 0 {
			expected = expected[:i]
		}
		if name != expected {
			t.Fatalf("parseScannedPackagesLine(%q): name=%q, want %q", line, name, expected)
		}
	})
}
