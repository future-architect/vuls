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
	"strings"
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

// FormatUpdatablePacksSummary returns a summary of updatable packages
func (ps Packages) FormatUpdatablePacksSummary() string {
	nUpdatable := 0
	for _, p := range ps {
		if p.NewVersion != "" {
			nUpdatable++
		}
	}
	return fmt.Sprintf("%d updatable packages", nUpdatable)
}

// FindOne search a element by name-newver-newrel-arch
func (ps Packages) FindOne(f func(Package) bool) (string, Package, bool) {
	for key, p := range ps {
		if f(p) {
			return key, p, true
		}
	}
	return "", Package{}, false
}

// Package has installed packages.
type Package struct {
	Name       string
	Version    string
	Release    string
	NewVersion string
	NewRelease string
	Arch       string
	Repository string
	Changelog  Changelog
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
func (p Package) FormatVersionFromTo(notFixedYet bool) string {
	to := p.FormatNewVer()
	if notFixedYet {
		to = "Not Fixed Yet"
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
		clog = "Failed to parse changelogs. For detials, check yourself"
	}
	buf = append(buf, packVer, delim.String(), clog)
	return strings.Join(buf, "\n")
}

// Changelog has contents of changelog and how to get it.
// Method: models.detectionMethodStr
type Changelog struct {
	Contents string
	Method   DetectionMethod
}
