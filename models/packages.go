package models

import (
	"bytes"
	"fmt"
	"regexp"
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
func (ps Packages) FindByFQPN(nameVerRel string) (*Package, error) {
	for _, p := range ps {
		if nameVerRel == p.FQPN() {
			return &p, nil
		}
	}
	return nil, xerrors.Errorf("Failed to find the package: %s", nameVerRel)
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
	ModularityLabel  string               `json:"modularitylabel"`
	Changelog        *Changelog           `json:"changelog,omitempty"`
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
func (p Package) FormatVersionFromTo(stat PackageFixStatus) string {
	to := p.FormatNewVer()
	if stat.NotFixedYet {
		if stat.FixState != "" {
			to = stat.FixState
		} else {
			to = "Not Fixed Yet"
		}
	} else if p.NewVersion == "" {
		to = "Unknown"
	}
	var fixedIn string
	if stat.FixedIn != "" {
		fixedIn = fmt.Sprintf(" (FixedIn: %s)", stat.FixedIn)
	}
	return fmt.Sprintf("%s-%s -> %s%s",
		p.Name, p.FormatVer(), to, fixedIn)
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
	PID             string     `json:"pid,omitempty"`
	Name            string     `json:"name,omitempty"`
	ListenPorts     []string   `json:"listenPorts,omitempty"`
	ListenPortStats []PortStat `json:"listenPortStats,omitempty"`
}

// PortStat has the result of parsing the port information to the address and port.
type PortStat struct {
	BindAddress     string   `json:"bindAddress"`
	Port            string   `json:"port"`
	PortReachableTo []string `json:"portReachableTo"`
}

// NewPortStat create a PortStat from ipPort str
func NewPortStat(ipPort string) (*PortStat, error) {
	if ipPort == "" {
		return &PortStat{}, nil
	}
	sep := strings.LastIndex(ipPort, ":")
	if sep == -1 {
		return nil, xerrors.Errorf("Failed to parse IP:Port: %s", ipPort)
	}
	return &PortStat{
		BindAddress: ipPort[:sep],
		Port:        ipPort[sep+1:],
	}, nil
}

// HasReachablePort checks if Package.AffectedProcs has PortReachableTo
func (p Package) HasReachablePort() bool {
	for _, ap := range p.AffectedProcs {
		for _, lp := range ap.ListenPortStats {
			if len(lp.PortReachableTo) > 0 {
				return true
			}
		}
	}
	return false
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
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Arch            string   `json:"arch"`
	ModularityLabel string   `json:"modularitylabel"`
	BinaryNames     []string `json:"binaryNames"`
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

// raspiPackNamePattern is a regular expression pattern to detect the Raspberry Pi specific package from the package name.
// e.g. libraspberrypi-dev, rpi-eeprom, python3-rpi.gpio, pi-bluetooth
var raspiPackNamePattern = regexp.MustCompile(`(.*raspberry.*|^rpi.*|.*-rpi.*|^pi-.*)`)

// raspiPackNamePattern is a regular expression pattern to detect the Raspberry Pi specific package from the version.
// e.g. ffmpeg 7:4.1.4-1+rpt7~deb10u1, vlc 3.0.10-0+deb10u1+rpt2
var raspiPackVersionPattern = regexp.MustCompile(`.+\+rp(t|i)\d+`)

// raspiPackNameList is a package name array of Raspberry Pi specific packages that are difficult to detect with regular expressions.
var raspiPackNameList = []string{"piclone", "pipanel", "pishutdown", "piwiz", "pixflat-icons"}

// IsRaspbianPackage judges whether it is a package related to Raspberry Pi from the package name and version
func IsRaspbianPackage(name, version string) bool {
	if raspiPackNamePattern.MatchString(name) || raspiPackVersionPattern.MatchString(version) {
		return true
	}
	for _, n := range raspiPackNameList {
		if n == name {
			return true
		}
	}

	return false
}
