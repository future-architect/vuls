package scanner

import (
	"strings"
	"testing"
)

// FuzzParseOSRelease drives random /etc/os-release content through
// (suse).parseOSRelease. Invariants: never panic; if name is non-empty then
// VERSION_ID was matched (so ver is non-empty too).
func FuzzParseOSRelease(f *testing.F) {
	seeds := []string{
		`CPE_NAME="cpe:/o:opensuse:opensuse:42.3"` + "\n" + `VERSION_ID="42.3"`,
		`CPE_NAME="cpe:/o:opensuse:tumbleweed:..."` + "\n" + `VERSION_ID="20231106"`,
		`CPE_NAME="cpe:/o:opensuse:leap:15.5"` + "\n" + `VERSION_ID="15.5"`,
		`CPE_NAME="cpe:/o:suse:sles:15:sp4"` + "\n" + `VERSION_ID="15.4"`,
		`CPE_NAME="cpe:/o:suse:sled:15"` + "\n" + `VERSION_ID="15"`,
		"",
		"\n",
		`VERSION_ID=""`,
		`CPE_NAME="cpe:/o:opensuse:opensuse"`,
		`CPE_NAME="cpe:/o:opensuse:opensuse"` + "\n" + `VERSION_ID=""`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, content string) {
		o := &suse{}
		name, ver := o.parseOSRelease(content)
		if name != "" {
			// tumbleweed early-returns "tumbleweed" without consulting VERSION_ID.
			if ver == "" && !strings.Contains(content, `CPE_NAME="cpe:/o:opensuse:tumbleweed`) {
				t.Fatalf("parseOSRelease(%q) returned name=%q with empty ver", content, name)
			}
		}
	})
}
