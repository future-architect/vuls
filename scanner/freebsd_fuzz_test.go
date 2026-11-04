package scanner

import (
	"testing"

	"github.com/future-architect/vuls/config"
)

// FuzzParsePkgVersion drives random `pkg version` outputs through
// parsePkgVersion. Invariants: never panic, returned map keys equal Name.
func FuzzParsePkgVersion(f *testing.F) {
	seeds := []string{
		"foo-1.0 ?\n",
		"bar-2.3.4 =\n",
		"baz-1.0 < needs updating (index has 2.0)\n",
		"qux-1.0 > newer than index\n",
		"",
		"\n",
		"   \n",
		"a b\n",
		"- =\n",
		"-1.0 ?\n",
		"name-only\n",
		"name -\n",
		"name <\n",
		"name < ( ( ( ( ( ( extra)\n",
		"name- ?\n",
		"foo-1.0 < a b c d e\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, stdout string) {
		o := newBsd(config.ServerInfo{})
		packs := o.parsePkgVersion(stdout)
		for key, pkg := range packs {
			if pkg.Name != key {
				t.Fatalf("parsePkgVersion(%q): map key %q != Name %q", stdout, key, pkg.Name)
			}
		}
	})
}

// FuzzParseBlock drives random pkg-audit blocks through parseBlock.
// Invariants: never panic.
func FuzzParseBlock(f *testing.F) {
	seeds := []string{
		"foo-1.0 is vulnerable:\nCVE: CVE-2024-1234\nWWW: https://vuxml.org/freebsd/abc.html\n",
		"is vulnerable:\nCVE:\nWWW:\n",
		" is vulnerable:\nCVE: x\nWWW: /a/b.html\n",
		"foo is vulnerable:\nCVE: A B C\n",
		"",
		"\n",
		"CVE:\n",
		"WWW:\n",
		"CVE:\nWWW:\n",
		"x-1 is vulnerable:\n",
		"x-1 is vulnerable:\nCVE:foo\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(_ *testing.T, block string) {
		o := newBsd(config.ServerInfo{})
		_, _, _ = o.parseBlock(block)
	})
}
