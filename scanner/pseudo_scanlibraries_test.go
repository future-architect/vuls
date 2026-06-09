package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
)

// TestPseudoScanLibraries_PartialFailure verifies that when one lockfile fails
// to be analyzed (e.g. a malformed file) while another is valid, the scan does
// not abort: the valid lockfile's libraries are still reported and the failure
// is recorded in warns (ScanResult.Warnings) rather than errs (ScanResult.Errors).
func TestPseudoScanLibraries_PartialFailure(t *testing.T) {
	// A malformed npm lockfile whose leading '{' is removed so parsing fails.
	malformed := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(malformed, []byte("\n\"name\": \"broken\",\n"), 0644); err != nil {
		t.Fatalf("failed to write malformed lockfile: %v", err)
	}

	// A valid npm v2 lockfile shared with the integration testdata.
	valid := filepath.Join("..", "integration", "data", "lockfile", "npm-v2", "package-lock.json")
	if _, err := os.Stat(valid); err != nil {
		t.Fatalf("valid lockfile not found: %v", err)
	}

	o := newPseudo(config.ServerInfo{
		Type:      constant.ServerTypePseudo,
		Lockfiles: []string{malformed, valid},
	})

	if err := o.scanLibraries(); err != nil {
		t.Fatalf("scanLibraries() returned error, want nil (scan must not abort): %v", err)
	}

	// The valid lockfile's libraries must still be reported.
	if len(o.LibraryScanners) == 0 {
		t.Errorf("LibraryScanners is empty, want libraries from the valid lockfile")
	}

	// The failure must land in warns, not errs.
	if len(o.warns) != 1 {
		t.Errorf("len(warns) = %d, want 1 (the malformed lockfile failure)", len(o.warns))
	}
	if len(o.errs) != 0 {
		t.Errorf("len(errs) = %d, want 0 (failure must not be recorded as an error)", len(o.errs))
	}
}

// TestPseudoScanLibraries_Success verifies the happy path: a single valid
// lockfile is analyzed, its libraries are reported, and neither warns nor errs
// is populated.
func TestPseudoScanLibraries_Success(t *testing.T) {
	// A valid npm v2 lockfile shared with the integration testdata.
	valid := filepath.Join("..", "integration", "data", "lockfile", "npm-v2", "package-lock.json")
	if _, err := os.Stat(valid); err != nil {
		t.Fatalf("valid lockfile not found: %v", err)
	}

	o := newPseudo(config.ServerInfo{
		Type:      constant.ServerTypePseudo,
		Lockfiles: []string{valid},
	})

	if err := o.scanLibraries(); err != nil {
		t.Fatalf("scanLibraries() returned error, want nil: %v", err)
	}

	if len(o.LibraryScanners) == 0 {
		t.Errorf("LibraryScanners is empty, want libraries from the valid lockfile")
	}
	if len(o.warns) != 0 {
		t.Errorf("len(warns) = %d, want 0", len(o.warns))
	}
	if len(o.errs) != 0 {
		t.Errorf("len(errs) = %d, want 0", len(o.errs))
	}
}
