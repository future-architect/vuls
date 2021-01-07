package config

import (
	"strings"
	"time"
)

const (
	// RedHat is
	RedHat = "redhat"

	// Debian is
	Debian = "debian"

	// Ubuntu is
	Ubuntu = "ubuntu"

	// CentOS is
	CentOS = "centos"

	// Fedora is
	// Fedora = "fedora"

	// Amazon is
	Amazon = "amazon"

	// Oracle is
	Oracle = "oracle"

	// FreeBSD is
	FreeBSD = "freebsd"

	// Raspbian is
	Raspbian = "raspbian"

	// Windows is
	Windows = "windows"

	// OpenSUSE is
	OpenSUSE = "opensuse"

	// OpenSUSELeap is
	OpenSUSELeap = "opensuse.leap"

	// SUSEEnterpriseServer is
	SUSEEnterpriseServer = "suse.linux.enterprise.server"

	// SUSEEnterpriseDesktop is
	SUSEEnterpriseDesktop = "suse.linux.enterprise.desktop"

	// SUSEOpenstackCloud is
	SUSEOpenstackCloud = "suse.openstack.cloud"

	// Alpine is
	Alpine = "alpine"

	// ServerTypePseudo is used for ServerInfo.Type, r.Family
	ServerTypePseudo = "pseudo"
)

type EOL struct {
	StandardSupportUntil time.Time
	ExtendedSupportUntil time.Time
	Ended                bool
}

func (e EOL) IsStandardSupportEnded(now time.Time) bool {
	return e.Ended ||
		!e.ExtendedSupportUntil.IsZero() && e.StandardSupportUntil.IsZero() ||
		!e.StandardSupportUntil.IsZero() && now.After(e.StandardSupportUntil)
}

func (e EOL) IsExtendedSuppportEnded(now time.Time) bool {
	return e.Ended ||
		!e.ExtendedSupportUntil.IsZero() && now.After(e.ExtendedSupportUntil)
}

// https://github.com/aquasecurity/trivy/blob/master/pkg/detector/ospkg/redhat/redhat.go#L20
func GetEOL(family, release string) (eol EOL, found bool) {
	switch family {
	case Amazon:
		//TODO
		eol, found = map[string]EOL{
			"1": {StandardSupportUntil: time.Date(2023, 6, 30, 23, 59, 59, 0, time.UTC)},
		}[release]
	case RedHat:
		// https://access.redhat.com/support/policy/updates/errata
		eol, found = map[string]EOL{
			"3": {Ended: true},
			"4": {Ended: true},
			"5": {Ended: true},
			"6": {
				StandardSupportUntil: time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
			},
			"7": {
				StandardSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
			},
			"8": {
				StandardSupportUntil: time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		}[major(release)]
	case CentOS:
		// https://en.wikipedia.org/wiki/CentOS#End-of-support_schedule
		// TODO Stream
		eol, found = map[string]EOL{
			"3": {Ended: true},
			"4": {Ended: true},
			"5": {Ended: true},
			"6": {Ended: true},
			"7": {StandardSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC)},
			"8": {StandardSupportUntil: time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case Oracle:
		eol, found = map[string]EOL{
			// Source:
			// https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
			// https://community.oracle.com/docs/DOC-917964
			"3": {Ended: true},
			"4": {Ended: true},
			"5": {Ended: true},
			"6": {
				StandardSupportUntil: time.Date(2021, 3, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2024, 3, 1, 23, 59, 59, 0, time.UTC),
			},
			"7": {
				StandardSupportUntil: time.Date(2024, 7, 1, 23, 59, 59, 0, time.UTC),
			},
			"8": {
				StandardSupportUntil: time.Date(2029, 7, 1, 23, 59, 59, 0, time.UTC),
			},
		}[major(release)]
	case Debian:
		eol, found = map[string]EOL{
			// https://wiki.debian.org/LTS
			"6":  {Ended: true},
			"7":  {Ended: true},
			"8":  {Ended: true},
			"9":  {StandardSupportUntil: time.Date(2022, 6, 30, 23, 59, 59, 0, time.UTC)},
			"10": {StandardSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case Ubuntu:
		// https://wiki.ubuntu.com/Releases
		eol, found = map[string]EOL{
			"14.10": {Ended: true},
			"14.04": {
				ExtendedSupportUntil: time.Date(2022, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"15.04": {Ended: true},
			"16.10": {Ended: true},
			"17.04": {Ended: true},
			"17.10": {Ended: true},
			"16.04": {
				StandardSupportUntil: time.Date(2021, 4, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2024, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"18.04": {
				StandardSupportUntil: time.Date(2023, 4, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2028, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"18.10": {Ended: true},
			"19.04": {Ended: true},
			"19.10": {Ended: true},
			"20.04": {
				StandardSupportUntil: time.Date(2025, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"21.04": {
				StandardSupportUntil: time.Date(2022, 1, 1, 23, 59, 59, 0, time.UTC),
			},
			"21.10": {
				StandardSupportUntil: time.Date(2022, 7, 1, 23, 59, 59, 0, time.UTC),
			},
		}[release]
	case SUSEEnterpriseServer:
		//TODO
	case Alpine:
		// https://github.com/aquasecurity/trivy/blob/master/pkg/detector/ospkg/alpine/alpine.go#L19
		eol, found = map[string]EOL{
			"2.0":  {Ended: true},
			"2.1":  {Ended: true},
			"2.2":  {Ended: true},
			"2.3":  {Ended: true},
			"2.4":  {Ended: true},
			"2.5":  {Ended: true},
			"2.6":  {Ended: true},
			"2.7":  {Ended: true},
			"3.0":  {Ended: true},
			"3.1":  {Ended: true},
			"3.2":  {Ended: true},
			"3.3":  {Ended: true},
			"3.4":  {Ended: true},
			"3.5":  {Ended: true},
			"3.6":  {Ended: true},
			"3.7":  {Ended: true},
			"3.8":  {Ended: true},
			"3.9":  {Ended: true},
			"3.10": {StandardSupportUntil: time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC)},
			"3.11": {StandardSupportUntil: time.Date(2021, 11, 1, 23, 59, 59, 0, time.UTC)},
			"3.12": {StandardSupportUntil: time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC)},
		}[release]
	}
	return
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}
