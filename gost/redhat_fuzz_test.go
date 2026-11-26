package gost

import (
	"strings"
	"testing"
)

// FuzzParseCwe drives random RedHat-CWE-encoded strings through
// (RedHat).parseCwe. Invariants:
//   - never panic,
//   - no entry contains the splitter characters '(', ')' or "->",
//   - no empty entry.
func FuzzParseCwe(f *testing.F) {
	seeds := []string{
		"CWE-79",
		"CWE-79->CWE-89",
		"(CWE-79)",
		"(CWE-79->CWE-89)",
		"CWE-79->(CWE-89)",
		"",
		"->",
		"()",
		"((()))",
		"->->->",
		"a(b)c->d",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, str string) {
		got := RedHat{}.parseCwe(str)
		for _, c := range got {
			if c == "" {
				t.Fatalf("parseCwe(%q) emitted empty entry: %v", str, got)
			}
			for _, splitter := range []string{"(", ")", "->"} {
				if strings.Contains(c, splitter) {
					t.Fatalf("parseCwe(%q) entry %q still contains splitter %q", str, c, splitter)
				}
			}
		}
	})
}
