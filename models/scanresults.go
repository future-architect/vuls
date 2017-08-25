/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package models

import (
	"bytes"
	"fmt"
	"time"

	"github.com/future-architect/vuls/config"
)

// ScanResults is a slide of ScanResult
type ScanResults []ScanResult

// ScanResult has the result of scanned CVE information.
type ScanResult struct {
	ScannedAt   time.Time
	ReportedAt  time.Time
	JSONVersion int
	Lang        string
	ServerUUID  string
	ServerName  string // TOML Section key
	Family      string
	Release     string
	Container   Container
	Platform    Platform

	// Scanned Vulns by SSH scan + CPE + OVAL
	ScannedCves VulnInfos

	RunningKernel Kernel
	Packages      Packages
	Errors        []string
	Optional      [][]interface{}

	Config struct {
		Scan   config.Config
		Report config.Config
	}
}

// Kernel has the Release, version and whether need restart
type Kernel struct {
	Release        string
	Version        string
	RebootRequired bool
}

// FilterByCvssOver is filter function.
func (r ScanResult) FilterByCvssOver(over float64) ScanResult {
	filtered := r.ScannedCves.Find(func(v VulnInfo) bool {
		v2Max := v.MaxCvss2Score()
		v3Max := v.MaxCvss3Score()
		max := v2Max.Value.Score
		if max < v3Max.Value.Score {
			max = v3Max.Value.Score
		}
		if over <= max {
			return true
		}
		return false
	})

	copiedScanResult := r
	copiedScanResult.ScannedCves = filtered
	return copiedScanResult
}

// FilterIgnoreCves is filter function.
func (r ScanResult) FilterIgnoreCves(cveIDs []string) ScanResult {
	filtered := r.ScannedCves.Find(func(v VulnInfo) bool {
		for _, c := range cveIDs {
			if v.CveID == c {
				return false
			}
		}
		return true
	})
	copiedScanResult := r
	copiedScanResult.ScannedCves = filtered
	return copiedScanResult
}

// ReportFileName returns the filename on localhost without extention
func (r ScanResult) ReportFileName() (name string) {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s", r.ServerName)
	}
	return fmt.Sprintf("%s@%s", r.Container.Name, r.ServerName)
}

// ReportKeyName returns the name of key on S3, Azure-Blob without extention
func (r ScanResult) ReportKeyName() (name string) {
	timestr := r.ScannedAt.Format(time.RFC3339)
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s/%s", timestr, r.ServerName)
	}
	return fmt.Sprintf("%s/%s@%s", timestr, r.Container.Name, r.ServerName)
}

// ServerInfo returns server name one line
func (r ScanResult) ServerInfo() string {
	if len(r.Container.ContainerID) == 0 {
		return fmt.Sprintf("%s (%s%s)",
			r.FormatServerName(), r.Family, r.Release)
	}
	return fmt.Sprintf(
		"%s (%s%s) on %s",
		r.FormatServerName(),
		r.Family,
		r.Release,
		r.ServerName,
	)
}

// ServerInfoTui returns server infromation for TUI sidebar
func (r ScanResult) ServerInfoTui() string {
	if len(r.Container.ContainerID) == 0 {
		line := fmt.Sprintf("%s (%s%s)",
			r.ServerName, r.Family, r.Release)
		if r.RunningKernel.RebootRequired {
			return "[Reboot] " + line
		}
		return line
	}

	fmtstr := "|-- %s (%s%s)"
	if r.RunningKernel.RebootRequired {
		fmtstr = "|-- [Reboot] %s (%s%s)"
	}
	return fmt.Sprintf(fmtstr, r.Container.Name, r.Family, r.Release)
}

// FormatServerName returns server and container name
func (r ScanResult) FormatServerName() (name string) {
	if len(r.Container.ContainerID) == 0 {
		name = r.ServerName
	} else {
		name = fmt.Sprintf("%s@%s",
			r.Container.Name, r.ServerName)
	}
	if r.RunningKernel.RebootRequired {
		name = "[Reboot Required] " + name
	}
	return
}

// FormatTextReportHeadedr returns header of text report
func (r ScanResult) FormatTextReportHeadedr() string {
	serverInfo := r.ServerInfo()
	var buf bytes.Buffer
	for i := 0; i < len(serverInfo); i++ {
		buf.WriteString("=")
	}
	return fmt.Sprintf("%s\n%s\n%s\t%s\n",
		r.ServerInfo(),
		buf.String(),
		r.ScannedCves.FormatCveSummary(),
		r.Packages.FormatUpdatablePacksSummary(),
	)
}

// Container has Container information
type Container struct {
	ContainerID string
	Name        string
	Image       string
	Type        string
}

// Platform has platform information
type Platform struct {
	Name       string // aws or azure or gcp or other...
	InstanceID string
}
