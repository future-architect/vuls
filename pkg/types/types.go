package types

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/config"
	"github.com/future-architect/vuls/pkg/db/types"
)

type Host struct {
	Name    string `json:"name,omitempty"`
	Family  string `json:"family,omitempty"`
	Release string `json:"release,omitempty"`

	ScannedAt       *time.Time `json:"scanned_at,omitempty"`
	ScannedVersion  string     `json:"scanned_version,omitempty"`
	ScannedRevision string     `json:"scanned_revision,omitempty"`
	ScanError       string     `json:"scan_error,omitempty"`

	DetecteddAt      *time.Time `json:"detectedd_at,omitempty"`
	DetectedVersion  string     `json:"detected_version,omitempty"`
	DetectedRevision string     `json:"detected_revision,omitempty"`
	DetectError      string     `json:"detect_error,omitempty"`

	ReportedAt       *time.Time `json:"reported_at,omitempty"`
	ReportedVersion  string     `json:"reported_version,omitempty"`
	ReportedRevision string     `json:"reported_revision,omitempty"`

	Packages    Packages            `json:"packages,omitempty"`
	ScannedCves map[string]VulnInfo `json:"scanned_cves,omitempty"`

	Config Config `json:"config,omitempty"`
}

func (h *Host) Exec(ctx context.Context, cmd string, sudo bool) (int, string, string, error) {
	if sudo {
		cmd = fmt.Sprintf("sudo -S %s", cmd)
	}
	switch h.Config.Type {
	case "local":
		execCmd := exec.CommandContext(ctx, "/bin/sh", "-c", cmd)
		if runtime.GOOS == "windows" {
			execCmd = exec.CommandContext(ctx, cmd)
		}
		var stdoutBuf, stderrBuf bytes.Buffer
		execCmd.Stdout = &stdoutBuf
		execCmd.Stderr = &stderrBuf
		if err := execCmd.Run(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				if s, ok := e.Sys().(syscall.WaitStatus); ok {
					return s.ExitStatus(), stdoutBuf.String(), stderrBuf.String(), nil
				} else {
					return 998, stdoutBuf.String(), stderrBuf.String(), nil
				}
			} else {
				return 999, stdoutBuf.String(), stderrBuf.String(), nil
			}
		} else {
			return 0, stdoutBuf.String(), stderrBuf.String(), nil
		}
	case "remote":
		sshBinPath, err := exec.LookPath("ssh")
		if err != nil {
			return 0, "", "", errors.Wrap(err, "look path to ssh")
		}

		args := []string{"-tt"}

		home, err := os.UserHomeDir()
		if err != nil {
			return 0, "", "", errors.Wrap(err, "find %s home directory")
		}
		args = append(args,
			"-o", "StrictHostKeyChecking=yes",
			"-o", "LogLevel=quiet",
			"-o", "ConnectionAttempts=3",
			"-o", "ConnectTimeout=10",
			"-o", "ControlMaster=auto",
			"-o", fmt.Sprintf("ControlPath=%s", filepath.Join(home, ".vuls", fmt.Sprintf("controlmaster-%%r-%s.%%p", h.Name))),
			"-o", "Controlpersist=10m",
			"-l", *h.Config.User,
		)
		if h.Config.Port != nil {
			args = append(args, "-p", *h.Config.Port)
		}
		if h.Config.SSHKey != nil {
			args = append(args, "-i", *h.Config.SSHKey, "-o", "PasswordAuthentication=no")
		}
		if runtime.GOOS == "windows" {
			args = append(args, *h.Config.Host, cmd)
		} else {
			args = append(args, *h.Config.Host, fmt.Sprintf("stty cols 1000; %s", cmd))
		}

		execCmd := exec.CommandContext(ctx, sshBinPath, args...)
		var stdoutBuf, stderrBuf bytes.Buffer
		execCmd.Stdout = &stdoutBuf
		execCmd.Stderr = &stderrBuf
		if err := execCmd.Run(); err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				if s, ok := e.Sys().(syscall.WaitStatus); ok {
					return s.ExitStatus(), stdoutBuf.String(), stderrBuf.String(), nil
				} else {
					return 998, stdoutBuf.String(), stderrBuf.String(), nil
				}
			} else {
				return 999, stdoutBuf.String(), stderrBuf.String(), nil
			}
		} else {
			return 0, stdoutBuf.String(), stderrBuf.String(), nil
		}
	default:
		return 0, "", "", errors.Errorf("%s is not implemented", h.Config.Type)
	}
}

type Packages struct {
	Kernel Kernel             `json:"kernel,omitempty"`
	OSPkg  map[string]Package `json:"ospkg,omitempty"`
	CPE    map[string]CPE     `json:"cpe,omitempty"`
	KB     []string           `json:"kb,omitempty"`
}

type Kernel struct {
	Version         string `json:"version,omitempty"`
	Release         string `json:"release,omitempty"`
	RebootRrequired bool   `json:"reboot_rrequired,omitempty"`
}

type Package struct {
	Name            string `json:"name,omitempty"`
	Version         string `json:"version,omitempty"`
	Release         string `json:"release,omitempty"`
	NewVersion      string `json:"new_version,omitempty"`
	NewRelease      string `json:"new_release,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Vendor          string `json:"vendor,omitempty"`
	Repository      string `json:"repository,omitempty"`
	ModularityLabel string `json:"modularity_label,omitempty"`

	SrcName    string `json:"src_name,omitempty"`
	SrcVersion string `json:"src_version,omitempty"`
	SrcArch    string `json:"src_arch,omitempty"`
}

type CPE struct {
	CPE       string `json:"cpe,omitempty"`
	RunningOn string `json:"running_on,omitempty"`
}

type VulnInfo struct {
	ID               string                         `json:"id,omitempty"`
	Content          map[string]types.Vulnerability `json:"content,omitempty"`
	AffectedPackages []AffectedPackage              `json:"affected_packages,omitempty"`
}

type AffectedPackage struct {
	Name   string `json:"name,omitempty"`
	Source string `json:"source,omitempty"`
	Status string `json:"status,omitempty"`
}

type Config struct {
	Type      string         `json:"type,omitempty"`
	Host      *string        `json:"host,omitempty"`
	Port      *string        `json:"port,omitempty"`
	User      *string        `json:"user,omitempty"`
	SSHConfig *string        `json:"ssh_config,omitempty"`
	SSHKey    *string        `json:"ssh_key,omitempty"`
	Scan      *config.Scan   `json:"scan,omitempty"`
	Detect    *config.Detect `json:"detect,omitempty"`
}
