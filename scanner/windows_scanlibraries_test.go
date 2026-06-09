//go:build windows

package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
)

// newWindowsForTest builds a windows scanner that executes locally through
// PowerShell. windows.scanLibraries reads lockfiles via PowerShell
// (Get-Location, [System.IO.File]::ReadAllBytes), so these tests only build and
// run under GOOS=windows (see the build constraint above) on a host with
// PowerShell available.
func newWindowsForTest(lockfiles []string) *windows {
	c := config.ServerInfo{
		Port:      "local",
		Host:      "localhost",
		Lockfiles: lockfiles,
	}
	c.Distro.Family = constant.Windows
	w := newWindows(c)
	w.shell = "powershell"
	return w
}

// TestWindowsScanLibraries_PartialFailure verifies that on Windows scans too, a
// single lockfile that fails to be analyzed does not abort the scan: the valid
// lockfile's libraries are still reported and the failure is recorded in warns
// (ScanResult.Warnings) rather than errs (ScanResult.Errors).
func TestWindowsScanLibraries_PartialFailure(t *testing.T) {
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

	w := newWindowsForTest([]string{malformed, valid})

	if err := w.scanLibraries(); err != nil {
		t.Fatalf("scanLibraries() returned error, want nil (scan must not abort): %v", err)
	}

	// The valid lockfile's libraries must still be reported.
	if len(w.LibraryScanners) == 0 {
		t.Errorf("LibraryScanners is empty, want libraries from the valid lockfile")
	}

	// The failure must land in warns, not errs.
	if len(w.warns) != 1 {
		t.Errorf("len(warns) = %d, want 1 (the malformed lockfile failure)", len(w.warns))
	}
	if len(w.errs) != 0 {
		t.Errorf("len(errs) = %d, want 0 (failure must not be recorded as an error)", len(w.errs))
	}
}

// TestWindowsScanLibraries_Success verifies the happy path: a single valid
// lockfile is analyzed, its libraries are reported, and neither warns nor errs
// is populated.
func TestWindowsScanLibraries_Success(t *testing.T) {
	// A valid npm v2 lockfile shared with the integration testdata.
	valid, err := filepath.Abs(filepath.Join("..", "integration", "data", "lockfile", "npm-v2", "package-lock.json"))
	if err != nil {
		t.Fatalf("failed to abs valid lockfile path: %v", err)
	}
	if _, err := os.Stat(valid); err != nil {
		t.Fatalf("valid lockfile not found: %v", err)
	}

	w := newWindowsForTest([]string{valid})

	if err := w.scanLibraries(); err != nil {
		t.Fatalf("scanLibraries() returned error, want nil: %v", err)
	}

	if len(w.LibraryScanners) == 0 {
		t.Errorf("LibraryScanners is empty, want libraries from the valid lockfile")
	}
	if len(w.warns) != 0 {
		t.Errorf("len(warns) = %d, want 0", len(w.warns))
	}
	if len(w.errs) != 0 {
		t.Errorf("len(errs) = %d, want 0", len(w.errs))
	}
}
