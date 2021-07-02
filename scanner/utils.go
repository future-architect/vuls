package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter"
	"golang.org/x/xerrors"
)

func isRunningKernel(pack models.Package, family string, kernel models.Kernel) (isKernel, running bool) {
	switch family {
	case constant.SUSEEnterpriseServer:
		if pack.Name == "kernel-default" {
			// Remove the last period and later because uname don't show that.
			ss := strings.Split(pack.Release, ".")
			rel := strings.Join(ss[0:len(ss)-1], ".")
			ver := fmt.Sprintf("%s-%s-default", pack.Version, rel)
			return true, kernel.Release == ver
		}
		return false, false

	case constant.RedHat, constant.Oracle, constant.CentOS, constant.Rocky, constant.Amazon:
		switch pack.Name {
		case "kernel", "kernel-devel", "kernel-core", "kernel-modules", "kernel-uek":
			ver := fmt.Sprintf("%s-%s.%s", pack.Version, pack.Release, pack.Arch)
			return true, kernel.Release == ver
		}
		return false, false

	default:
		logging.Log.Warnf("Reboot required is not implemented yet: %s, %v", family, kernel)
	}
	return false, false
}

// EnsureResultDir ensures the directory for scan results
func EnsureResultDir(resultsDir string, scannedAt time.Time) (currentDir string, err error) {
	jsonDirName := scannedAt.Format(time.RFC3339)
	if resultsDir == "" {
		wd, _ := os.Getwd()
		resultsDir = filepath.Join(wd, "results")
	}
	jsonDir := filepath.Join(resultsDir, jsonDirName)
	if err := os.MkdirAll(jsonDir, 0700); err != nil {
		return "", xerrors.Errorf("Failed to create dir: %w", err)
	}

	symlinkPath := filepath.Join(resultsDir, "current")
	if _, err := os.Lstat(symlinkPath); err == nil {
		if err := os.Remove(symlinkPath); err != nil {
			return "", xerrors.Errorf(
				"Failed to remove symlink. path: %s, err: %w", symlinkPath, err)
		}
	}

	if err := os.Symlink(jsonDir, symlinkPath); err != nil {
		return "", xerrors.Errorf(
			"Failed to create symlink: path: %s, err: %w", symlinkPath, err)
	}
	return jsonDir, nil
}

func writeScanResults(jsonDir string, results models.ScanResults) error {
	ws := []reporter.ResultWriter{reporter.LocalFileWriter{
		CurrentDir: jsonDir,
		FormatJSON: true,
	}}
	for _, w := range ws {
		if err := w.Write(results...); err != nil {
			return xerrors.Errorf("Failed to write summary: %s", err)
		}
	}

	reporter.StdoutWriter{}.WriteScanSummary(results...)

	errServerNames := []string{}
	for _, r := range results {
		if 0 < len(r.Errors) {
			errServerNames = append(errServerNames, r.ServerName)
		}
	}
	if 0 < len(errServerNames) {
		return fmt.Errorf("An error occurred on %s", errServerNames)
	}
	return nil
}
