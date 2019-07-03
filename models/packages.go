/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Corporation , Japan.

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
	"strings"

	"golang.org/x/xerrors"
)

// Packages is Map of Package
// { "package-name": Package }
type Packages map[string]Package

// NewPackages create Packages
func NewPackages(packs ...Package) Packages {
	m := Packages{}
	for _, pack := range packs {
		m[pack.Name] = pack
	}
	return m
}

// MergeNewVersion merges candidate version information to the receiver struct
func (ps Packages) MergeNewVersion(as Packages) {
	for name, pack := range ps {
		pack.NewVersion = pack.Version
		pack.NewRelease = pack.Release
		ps[name] = pack
	}

	for _, a := range as {
		if pack, ok := ps[a.Name]; ok {
			pack.NewVersion = a.NewVersion
			pack.NewRelease = a.NewRelease
			pack.Repository = a.Repository
			ps[a.Name] = pack
		}
	}
}

// Merge returns merged map (immutable)
func (ps Packages) Merge(other Packages) Packages {
	merged := Packages{}
	for k, v := range ps {
		merged[k] = v
	}
	for k, v := range other {
		merged[k] = v
	}
	return merged
}

// FindOne search a element
func (ps Packages) FindOne(f func(Package) bool) (string, Package, bool) {
	for key, p := range ps {
		if f(p) {
			return key, p, true
		}
	}
	return "", Package{}, false
}

// FindByFQPN search a package by Fully-Qualified-Package-Name
func (ps Packages) FindByFQPN(nameVerRelArc string) (*Package, error) {
	for _, p := range ps {
		if nameVerRelArc == p.FQPN() {
			return &p, nil
		}
	}
	return nil, xerrors.Errorf("Failed to find the package: %s", nameVerRelArc)
}

// Package has installed binary packages.
type Package struct {
	Name             string               `json:"name"`
	Version          string               `json:"version"`
	Release          string               `json:"release"`
	NewVersion       string               `json:"newVersion"`
	NewRelease       string               `json:"newRelease"`
	Arch             string               `json:"arch"`
	Repository       string               `json:"repository"`
	Changelog        Changelog            `json:"changelog"`
	AffectedProcs    []AffectedProcess    `json:",omitempty"`
	NeedRestartProcs []NeedRestartProcess `json:",omitempty"`
}

// FQPN returns Fully-Qualified-Package-Name
// name-version-release.arch
func (p Package) FQPN() string {
	fqpn := p.Name
	if p.Version != "" {
		fqpn += fmt.Sprintf("-%s", p.Version)
	}
	if p.Release != "" {
		fqpn += fmt.Sprintf("-%s", p.Release)
	}
	if p.Arch != "" {
		fqpn += fmt.Sprintf(".%s", p.Arch)
	}
	return fqpn
}

// FormatVer returns package version-release
func (p Package) FormatVer() string {
	ver := p.Version
	if 0 < len(p.Release) {
		ver = fmt.Sprintf("%s-%s", ver, p.Release)
	}
	return ver
}

// FormatNewVer returns package version-release
func (p Package) FormatNewVer() string {
	ver := p.NewVersion
	if 0 < len(p.NewRelease) {
		ver = fmt.Sprintf("%s-%s", ver, p.NewRelease)
	}
	return ver
}

// FormatVersionFromTo formats installed and new package version
func (p Package) FormatVersionFromTo(notFixedYet bool, status string) string {
	to := p.FormatNewVer()
	if notFixedYet {
		if status != "" {
			to = status
		} else {
			to = "Not Fixed Yet"
		}
	} else if p.NewVersion == "" {
		to = "Unknown"
	}
	return fmt.Sprintf("%s-%s -> %s", p.Name, p.FormatVer(), to)
}

// FormatChangelog formats the changelog
func (p Package) FormatChangelog() string {
	buf := []string{}
	packVer := fmt.Sprintf("%s-%s -> %s",
		p.Name, p.FormatVer(), p.FormatNewVer())
	var delim bytes.Buffer
	for i := 0; i < len(packVer); i++ {
		delim.WriteString("-")
	}

	clog := p.Changelog.Contents
	if lines := strings.Split(clog, "\n"); len(lines) != 0 {
		clog = strings.Join(lines[0:len(lines)-1], "\n")
	}

	switch p.Changelog.Method {
	case FailedToGetChangelog:
		clog = "No changelogs"
	case FailedToFindVersionInChangelog:
		clog = "Failed to parse changelogs. For details, check yourself"
	}
	buf = append(buf, packVer, delim.String(), clog)
	return strings.Join(buf, "\n")
}

// Changelog has contents of changelog and how to get it.
// Method: models.detectionMethodStr
type Changelog struct {
	Contents string          `json:"contents"`
	Method   DetectionMethod `json:"method"`
}

// AffectedProcess keep a processes information affected by software update
type AffectedProcess struct {
	PID         string   `json:"pid,omitempty"`
	Name        string   `json:"name,omitempty"`
	ListenPorts []string `json:"listenPorts,omitempty"`
}

// NeedRestartProcess keep a processes information affected by software update
type NeedRestartProcess struct {
	PID         string `json:"pid"`
	Path        string `json:"path"`
	ServiceName string `json:"serviceName"`
	InitSystem  string `json:"initSystem"`
	HasInit     bool   `json:"-"`
}

// SrcPackage has installed source package information.
// Debian based Linux has both of package and source information in dpkg.
// OVAL database often includes a source version (Not a binary version),
// so it is also needed to capture source version for OVAL version comparison.
// https://github.com/future-architect/vuls/issues/504
type SrcPackage struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	BinaryNames []string `json:"binaryNames"`
}

// AddBinaryName add the name if not exists
func (s *SrcPackage) AddBinaryName(name string) {
	found := false
	for _, n := range s.BinaryNames {
		if n == name {
			return
		}
	}
	if !found {
		s.BinaryNames = append(s.BinaryNames, name)
	}
}

// SrcPackages is Map of SrcPackage
// { "package-name": SrcPackage }
type SrcPackages map[string]SrcPackage

// FindByBinName finds by bin-package-name
func (s SrcPackages) FindByBinName(name string) (*SrcPackage, bool) {
	for _, p := range s {
		for _, binName := range p.BinaryNames {
			if binName == name {
				return &p, true
			}
		}
	}
	return nil, false
}
