package config

import (
	"strings"
	"testing"
)

// FuzzToCpeURI drives random CPE strings through toCpeURI. Invariants:
//   - never panic,
//   - if err == nil, the returned URI starts with "cpe:/" (CPE 2.2 form).
func FuzzToCpeURI(f *testing.F) {
	seeds := []string{
		`cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*`,
		`cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*`,
		`cpe:/a:vendor:product:1.0`,
		`cpe:/o:linux:linux_kernel:5.10`,
		`cpe:/`,
		`cpe:2.3:`,
		`cpe:2.3`,
		`cpe:2.3:a:`,
		`cpe:/a:`,
		``,
		`not-a-cpe`,
		`cpe:2.3:a:v:p:1\:2:*:*:*:*:*:*:*`,
		`cpe:/a:vendor:product:1\:2`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, cpename string) {
		got, err := toCpeURI(cpename)
		if err != nil {
			return
		}
		if !strings.HasPrefix(got, "cpe:/") {
			t.Fatalf("toCpeURI(%q) = %q: missing cpe:/ prefix", cpename, got)
		}
	})
}
