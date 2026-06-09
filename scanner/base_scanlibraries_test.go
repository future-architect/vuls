package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/logging"
)

// TestBaseScanLibraries_PartialFailure verifies the partial-failure behavior of
// the normal (non-pseudo) scan path: when one lockfile fails to be analyzed
// while another is valid, base.scanLibraries does not abort, the valid
// lockfile's libraries are still reported, and the failure is recorded in warns
// (ScanResult.Warnings) rather than errs (ScanResult.Errors).
//
// It exercises the real exec path via a local server (Port "local"), so it
// shells out to stat/cat and therefore only runs on a unix-like host.
func TestBaseScanLibraries_PartialFailure(t *testing.T) {
	// A malformed npm lockfile whose leading '{' is removed so parsing fails.
	malformed := filepath.Join(t.TempDir(), "package-lock.json")
	if err := os.WriteFile(malformed, []byte("\n\"name\": \"broken\",\n"), 0644); err != nil {
		t.Fatalf("failed to write malformed lockfile: %v", err)
	}

	// A valid npm v2 lockfile shared with the integration testdata.
	valid, err := filepath.Abs(filepath.Join("..", "integration", "data", "lockfile", "npm-v2", "package-lock.json"))
	if err != nil {
		t.Fatalf("failed to abs valid lockfile path: %v", err)
	}
	if _, err := os.Stat(valid); err != nil {
		t.Fatalf("valid lockfile not found: %v", err)
	}

	l := &base{}
	l.log = logging.NewNormalLogger()
	l.setServerInfo(config.ServerInfo{
		Port:      "local",
		Host:      "localhost",
		Lockfiles: []string{malformed, valid},
	})

	if err := l.scanLibraries(); err != nil {
		t.Fatalf("scanLibraries() returned error, want nil (scan must not abort): %v", err)
	}

	// The valid lockfile's libraries must still be reported.
	if len(l.LibraryScanners) == 0 {
		t.Errorf("LibraryScanners is empty, want libraries from the valid lockfile")
	}

	// The failure must land in warns, not errs.
	if len(l.warns) != 1 {
		t.Errorf("len(warns) = %d, want 1 (the malformed lockfile failure)", len(l.warns))
	}
	if len(l.errs) != 0 {
		t.Errorf("len(errs) = %d, want 0 (failure must not be recorded as an error)", len(l.errs))
	}
}

// TestBaseScanLibraries_Success verifies the happy path of the normal scan:
// a single valid lockfile is analyzed, its libraries are reported, and neither
// warns nor errs is populated.
//
// Like the partial-failure test it drives the real exec path via a local
// server, so it shells out to stat/cat and only runs on a unix-like host.
func TestBaseScanLibraries_Success(t *testing.T) {
	// A valid npm v2 lockfile shared with the integration testdata.
	valid, err := filepath.Abs(filepath.Join("..", "integration", "data", "lockfile", "npm-v2", "package-lock.json"))
	if err != nil {
		t.Fatalf("failed to abs valid lockfile path: %v", err)
	}
	if _, err := os.Stat(valid); err != nil {
		t.Fatalf("valid lockfile not found: %v", err)
	}

	l := &base{}
	l.log = logging.NewNormalLogger()
	l.setServerInfo(config.ServerInfo{
		Port:      "local",
		Host:      "localhost",
		Lockfiles: []string{valid},
	})

	if err := l.scanLibraries(); err != nil {
		t.Fatalf("scanLibraries() returned error, want nil: %v", err)
	}

	if len(l.LibraryScanners) == 0 {
		t.Errorf("LibraryScanners is empty, want libraries from the valid lockfile")
	}
	if len(l.warns) != 0 {
		t.Errorf("len(warns) = %d, want 0", len(l.warns))
	}
	if len(l.errs) != 0 {
		t.Errorf("len(errs) = %d, want 0", len(l.errs))
	}
}
