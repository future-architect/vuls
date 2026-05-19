//go:build !scanner

package detector

import (
	"os"
	"path/filepath"
	"testing"
)

func TestListValidJSONDirs_SortedDescending(t *testing.T) {
	root := t.TempDir()

	names := []string{
		"2026-04-24T08-22-31+0000",
		"2026-04-25T08-27-25+0000",
		"2026-04-25T17-52-14+0000",
		"2026-04-25T18-20-55+0000",
		"2026-04-25T19-48-34+0000",
		"2026-04-27T13-02-05+0000",
		"2026-04-28T12-56-45+0000",
		"2026-04-29T12-57-26+0000",
		"2026-04-30T12-57-38+0000",
		"2026-05-01T12-57-29+0000",
		"2026-05-01T15-17-13+0000",
		"2026-05-01T15-33-21+0000",
		"not-a-timestamp",
	}
	for _, n := range names {
		if err := os.Mkdir(filepath.Join(root, n), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", n, err)
		}
	}

	got, err := ListValidJSONDirs(root)
	if err != nil {
		t.Fatalf("ListValidJSONDirs: %v", err)
	}

	want := []string{
		filepath.Join(root, "2026-05-01T15-33-21+0000"),
		filepath.Join(root, "2026-05-01T15-17-13+0000"),
		filepath.Join(root, "2026-05-01T12-57-29+0000"),
		filepath.Join(root, "2026-04-30T12-57-38+0000"),
		filepath.Join(root, "2026-04-29T12-57-26+0000"),
		filepath.Join(root, "2026-04-28T12-56-45+0000"),
		filepath.Join(root, "2026-04-27T13-02-05+0000"),
		filepath.Join(root, "2026-04-25T19-48-34+0000"),
		filepath.Join(root, "2026-04-25T18-20-55+0000"),
		filepath.Join(root, "2026-04-25T17-52-14+0000"),
		filepath.Join(root, "2026-04-25T08-27-25+0000"),
		filepath.Join(root, "2026-04-24T08-22-31+0000"),
	}

	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want=%d\ngot=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("dirs[%d] = %s, want %s", i, got[i], want[i])
		}
	}
}
