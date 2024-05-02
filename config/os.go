package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/future-architect/vuls/constant"
)

// EOL has End-of-Life information
type EOL struct {
	StandardSupportUntil time.Time
	ExtendedSupportUntil time.Time
	Ended                bool
}

// IsStandardSupportEnded checks now is under standard support
func (e EOL) IsStandardSupportEnded(now time.Time) bool {
	return e.Ended ||
		!e.ExtendedSupportUntil.IsZero() && e.StandardSupportUntil.IsZero() ||
		!e.StandardSupportUntil.IsZero() && now.After(e.StandardSupportUntil)
}

// IsExtendedSuppportEnded checks now is under extended support
func (e EOL) IsExtendedSuppportEnded(now time.Time) bool {
	if e.Ended {
		return true
	}
	if e.StandardSupportUntil.IsZero() && e.ExtendedSupportUntil.IsZero() {
		return false
	}
	return !e.ExtendedSupportUntil.IsZero() && now.After(e.ExtendedSupportUntil) ||
		e.ExtendedSupportUntil.IsZero() && now.After(e.StandardSupportUntil)
}

// GetEOL return EOL information for the OS-release passed by args
// https://github.com/aquasecurity/trivy/blob/master/pkg/detector/ospkg/redhat/redhat.go#L20
func GetEOL(family, release string) (eol EOL, found bool) {
	switch family {
	case constant.Amazon:
		eol, found = map[string]EOL{
			"1":    {StandardSupportUntil: time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)},
			"2":    {StandardSupportUntil: time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC)},
			"2022": {StandardSupportUntil: time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)},
			"2023": {StandardSupportUntil: time.Date(2027, 6, 30, 23, 59, 59, 0, time.UTC)},
			"2025": {StandardSupportUntil: time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC)},
			"2027": {StandardSupportUntil: time.Date(2031, 6, 30, 23, 59, 59, 0, time.UTC)},
			"2029": {StandardSupportUntil: time.Date(2033, 6, 30, 23, 59, 59, 0, time.UTC)},
		}[getAmazonLinuxVersion(release)]
	case constant.RedHat:
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
				ExtendedSupportUntil: time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC),
			},
			"8": {
				StandardSupportUntil: time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2031, 5, 31, 23, 59, 59, 0, time.UTC),
			},
			"9": {
				StandardSupportUntil: time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2034, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		}[major(release)]
	case constant.CentOS:
		// https://en.wikipedia.org/wiki/CentOS#End-of-support_schedule
		eol, found = map[string]EOL{
			"3":       {Ended: true},
			"4":       {Ended: true},
			"5":       {Ended: true},
			"6":       {Ended: true},
			"7":       {StandardSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC)},
			"8":       {StandardSupportUntil: time.Date(2021, 12, 31, 23, 59, 59, 0, time.UTC)},
			"stream8": {StandardSupportUntil: time.Date(2024, 5, 31, 23, 59, 59, 0, time.UTC)},
			"stream9": {StandardSupportUntil: time.Date(2027, 5, 31, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case constant.Alma:
		eol, found = map[string]EOL{
			"8": {StandardSupportUntil: time.Date(2029, 12, 31, 23, 59, 59, 0, time.UTC)},
			"9": {StandardSupportUntil: time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case constant.Rocky:
		eol, found = map[string]EOL{
			"8": {StandardSupportUntil: time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC)},
			"9": {StandardSupportUntil: time.Date(2032, 5, 31, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case constant.Oracle:
		eol, found = map[string]EOL{
			// Source:
			// https://www.oracle.com/a/ocom/docs/elsp-lifetime-069338.pdf
			// https://community.oracle.com/docs/DOC-917964
			"3": {Ended: true},
			"4": {Ended: true},
			"5": {Ended: true},
			"6": {
				StandardSupportUntil: time.Date(2021, 3, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2024, 6, 1, 23, 59, 59, 0, time.UTC),
			},
			"7": {
				StandardSupportUntil: time.Date(2024, 7, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2026, 6, 1, 23, 59, 59, 0, time.UTC),
			},
			"8": {
				StandardSupportUntil: time.Date(2029, 7, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2031, 7, 1, 23, 59, 59, 0, time.UTC),
			},
			"9": {
				StandardSupportUntil: time.Date(2032, 6, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2034, 6, 1, 23, 59, 59, 0, time.UTC),
			},
		}[major(release)]
	case constant.Debian:
		eol, found = map[string]EOL{
			// https://wiki.debian.org/LTS
			"6":  {Ended: true},
			"7":  {Ended: true},
			"8":  {Ended: true},
			"9":  {StandardSupportUntil: time.Date(2022, 6, 30, 23, 59, 59, 0, time.UTC)},
			"10": {StandardSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC)},
			"11": {StandardSupportUntil: time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)},
			"12": {StandardSupportUntil: time.Date(2028, 6, 30, 23, 59, 59, 0, time.UTC)},
			// "13": {StandardSupportUntil: time.Date(2030, 6, 30, 23, 59, 59, 0, time.UTC)},
			// "14": {StandardSupportUntil: time.Date(2032, 6, 30, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case constant.Raspbian:
		// Not found
		eol, found = map[string]EOL{}[major(release)]
	case constant.Ubuntu:
		// https://wiki.ubuntu.com/Releases
		eol, found = map[string]EOL{
			"6.06":  {Ended: true},
			"6.10":  {Ended: true},
			"7.04":  {Ended: true},
			"7.10":  {Ended: true},
			"8.04":  {Ended: true},
			"8.10":  {Ended: true},
			"9.04":  {Ended: true},
			"9.10":  {Ended: true},
			"10.04": {Ended: true},
			"10.10": {Ended: true},
			"11.04": {Ended: true},
			"11.10": {Ended: true},
			"12.04": {Ended: true},
			"12.10": {Ended: true},
			"13.04": {Ended: true},
			"13.10": {Ended: true},
			"14.04": {
				ExtendedSupportUntil: time.Date(2022, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"14.10": {Ended: true},
			"15.04": {Ended: true},
			"15.10": {Ended: true},
			"16.04": {
				StandardSupportUntil: time.Date(2021, 4, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2024, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"16.10": {Ended: true},
			"17.04": {Ended: true},
			"17.10": {Ended: true},
			"18.04": {
				StandardSupportUntil: time.Date(2023, 4, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2028, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"18.10": {Ended: true},
			"19.04": {Ended: true},
			"19.10": {Ended: true},
			"20.04": {
				StandardSupportUntil: time.Date(2025, 4, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2030, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"20.10": {
				StandardSupportUntil: time.Date(2021, 7, 22, 23, 59, 59, 0, time.UTC),
			},
			"21.04": {
				StandardSupportUntil: time.Date(2022, 1, 20, 23, 59, 59, 0, time.UTC),
			},
			"21.10": {
				StandardSupportUntil: time.Date(2022, 7, 14, 23, 59, 59, 0, time.UTC),
			},
			"22.04": {
				StandardSupportUntil: time.Date(2027, 4, 1, 23, 59, 59, 0, time.UTC),
				ExtendedSupportUntil: time.Date(2032, 4, 1, 23, 59, 59, 0, time.UTC),
			},
			"22.10": {
				StandardSupportUntil: time.Date(2023, 7, 20, 23, 59, 59, 0, time.UTC),
			},
			"23.04": {
				StandardSupportUntil: time.Date(2024, 1, 25, 23, 59, 59, 0, time.UTC),
			},
			"23.10": {
				StandardSupportUntil: time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC),
			},
			"24.04": {
				StandardSupportUntil: time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC),
			},
		}[release]
	case constant.OpenSUSE:
		// https://en.opensuse.org/Lifetime
		eol, found = map[string]EOL{
			"10.2":       {Ended: true},
			"10.3":       {Ended: true},
			"11.0":       {Ended: true},
			"11.1":       {Ended: true},
			"11.2":       {Ended: true},
			"11.3":       {Ended: true},
			"11.4":       {Ended: true},
			"12.1":       {Ended: true},
			"12.2":       {Ended: true},
			"12.3":       {Ended: true},
			"13.1":       {Ended: true},
			"13.2":       {Ended: true},
			"tumbleweed": {},
		}[release]
	case constant.OpenSUSELeap:
		// https://en.opensuse.org/Lifetime
		eol, found = map[string]EOL{
			"42.1": {Ended: true},
			"42.2": {Ended: true},
			"42.3": {Ended: true},
			"15.0": {Ended: true},
			"15.1": {Ended: true},
			"15.2": {Ended: true},
			"15.3": {StandardSupportUntil: time.Date(2022, 11, 30, 23, 59, 59, 0, time.UTC)},
			"15.4": {StandardSupportUntil: time.Date(2023, 11, 30, 23, 59, 59, 0, time.UTC)},
			"15.5": {StandardSupportUntil: time.Date(2024, 12, 31, 23, 59, 59, 0, time.UTC)},
		}[release]
	case constant.SUSEEnterpriseServer:
		// https://www.suse.com/lifecycle
		eol, found = map[string]EOL{
			"11":   {Ended: true},
			"11.1": {Ended: true},
			"11.2": {Ended: true},
			"11.3": {Ended: true},
			"11.4": {Ended: true},
			"12":   {Ended: true},
			"12.1": {Ended: true},
			"12.2": {Ended: true},
			"12.3": {Ended: true},
			"12.4": {Ended: true},
			"12.5": {StandardSupportUntil: time.Date(2024, 10, 31, 23, 59, 59, 0, time.UTC)},
			"15":   {Ended: true},
			"15.1": {Ended: true},
			"15.2": {Ended: true},
			"15.3": {StandardSupportUntil: time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC)},
			"15.4": {StandardSupportUntil: time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)},
			"15.5": {},
			"15.6": {},
			"15.7": {StandardSupportUntil: time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC)},
		}[release]
	case constant.SUSEEnterpriseDesktop:
		// https://www.suse.com/lifecycle
		eol, found = map[string]EOL{
			"11":   {Ended: true},
			"11.1": {Ended: true},
			"11.2": {Ended: true},
			"11.3": {Ended: true},
			"11.4": {Ended: true},
			"12":   {Ended: true},
			"12.1": {Ended: true},
			"12.2": {Ended: true},
			"12.3": {Ended: true},
			"12.4": {Ended: true},
			"15":   {Ended: true},
			"15.1": {Ended: true},
			"15.2": {Ended: true},
			"15.3": {StandardSupportUntil: time.Date(2022, 12, 31, 23, 59, 59, 0, time.UTC)},
			"15.4": {StandardSupportUntil: time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)},
			"15.5": {},
			"15.6": {},
			"15.7": {StandardSupportUntil: time.Date(2028, 7, 31, 23, 59, 59, 0, time.UTC)},
		}[release]
	case constant.Alpine:
		// https://github.com/aquasecurity/trivy/blob/master/pkg/detector/ospkg/alpine/alpine.go#L19
		// https://alpinelinux.org/releases/
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
			"3.13": {StandardSupportUntil: time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC)},
			"3.14": {StandardSupportUntil: time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC)},
			"3.15": {StandardSupportUntil: time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC)},
			"3.16": {StandardSupportUntil: time.Date(2024, 5, 23, 23, 59, 59, 0, time.UTC)},
			"3.17": {StandardSupportUntil: time.Date(2024, 11, 22, 23, 59, 59, 0, time.UTC)},
			"3.18": {StandardSupportUntil: time.Date(2025, 5, 9, 23, 59, 59, 0, time.UTC)},
		}[majorDotMinor(release)]
	case constant.FreeBSD:
		// https://www.freebsd.org/security/
		eol, found = map[string]EOL{
			"7":  {Ended: true},
			"8":  {Ended: true},
			"9":  {Ended: true},
			"10": {Ended: true},
			"11": {StandardSupportUntil: time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC)},
			"12": {StandardSupportUntil: time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC)},
			"13": {StandardSupportUntil: time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)},
			"14": {StandardSupportUntil: time.Date(2028, 11, 21, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case constant.Fedora:
		// https://docs.fedoraproject.org/en-US/releases/eol/
		// https://endoflife.date/fedora
		eol, found = map[string]EOL{
			"32": {StandardSupportUntil: time.Date(2021, 5, 24, 23, 59, 59, 0, time.UTC)},
			"33": {StandardSupportUntil: time.Date(2021, 11, 29, 23, 59, 59, 0, time.UTC)},
			"34": {StandardSupportUntil: time.Date(2022, 6, 6, 23, 59, 59, 0, time.UTC)},
			"35": {StandardSupportUntil: time.Date(2022, 12, 12, 23, 59, 59, 0, time.UTC)},
			"36": {StandardSupportUntil: time.Date(2023, 5, 16, 23, 59, 59, 0, time.UTC)},
			"37": {StandardSupportUntil: time.Date(2023, 12, 15, 23, 59, 59, 0, time.UTC)},
			"38": {StandardSupportUntil: time.Date(2024, 5, 14, 23, 59, 59, 0, time.UTC)},
			"39": {StandardSupportUntil: time.Date(2024, 11, 12, 23, 59, 59, 0, time.UTC)},
		}[major(release)]
	case constant.Windows:
		// https://learn.microsoft.com/ja-jp/lifecycle/products/?products=windows

		lhs, rhs, _ := strings.Cut(strings.TrimSuffix(release, "(Server Core installation)"), "for")
		switch strings.TrimSpace(lhs) {
		case "Windows 7":
			eol, found = EOL{StandardSupportUntil: time.Date(2013, 4, 9, 23, 59, 59, 0, time.UTC)}, true
			if strings.Contains(rhs, "Service Pack 1") {
				eol, found = EOL{StandardSupportUntil: time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC)}, true
			}
		case "Windows 8":
			eol, found = EOL{StandardSupportUntil: time.Date(2016, 1, 12, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 8.1":
			eol, found = EOL{StandardSupportUntil: time.Date(2023, 1, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10":
			eol, found = EOL{StandardSupportUntil: time.Date(2017, 5, 9, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1511":
			eol, found = EOL{StandardSupportUntil: time.Date(2017, 10, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1607":
			eol, found = EOL{StandardSupportUntil: time.Date(2018, 4, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1703":
			eol, found = EOL{StandardSupportUntil: time.Date(2018, 10, 9, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1709":
			eol, found = EOL{StandardSupportUntil: time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1803":
			eol, found = EOL{StandardSupportUntil: time.Date(2019, 11, 12, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1809":
			eol, found = EOL{StandardSupportUntil: time.Date(2020, 11, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1903":
			eol, found = EOL{StandardSupportUntil: time.Date(2020, 12, 8, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 1909":
			eol, found = EOL{StandardSupportUntil: time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 2004":
			eol, found = EOL{StandardSupportUntil: time.Date(2021, 12, 14, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 20H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2022, 5, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 21H1":
			eol, found = EOL{StandardSupportUntil: time.Date(2022, 12, 13, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 21H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2024, 6, 11, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 10 Version 22H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 11 Version 21H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2024, 10, 8, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 11 Version 22H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2025, 10, 14, 23, 59, 59, 0, time.UTC)}, true
		case "Windows 11 Version 23H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2026, 11, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server 2008":
			eol, found = EOL{StandardSupportUntil: time.Date(2011, 7, 12, 23, 59, 59, 0, time.UTC)}, true
			if strings.Contains(rhs, "Service Pack 2") {
				eol, found = EOL{StandardSupportUntil: time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC)}, true
			}
		case "Windows Server 2008 R2":
			eol, found = EOL{StandardSupportUntil: time.Date(2013, 4, 9, 23, 59, 59, 0, time.UTC)}, true
			if strings.Contains(rhs, "Service Pack 1") {
				eol, found = EOL{StandardSupportUntil: time.Date(2020, 1, 14, 23, 59, 59, 0, time.UTC)}, true
			}
		case "Windows Server 2012":
			eol, found = EOL{StandardSupportUntil: time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server 2012 R2":
			eol, found = EOL{StandardSupportUntil: time.Date(2023, 10, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server 2016":
			eol, found = EOL{StandardSupportUntil: time.Date(2027, 1, 12, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 1709":
			eol, found = EOL{StandardSupportUntil: time.Date(2019, 4, 9, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 1803":
			eol, found = EOL{StandardSupportUntil: time.Date(2019, 11, 12, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 1809":
			eol, found = EOL{StandardSupportUntil: time.Date(2020, 11, 10, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server 2019":
			eol, found = EOL{StandardSupportUntil: time.Date(2029, 1, 9, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 1903":
			eol, found = EOL{StandardSupportUntil: time.Date(2020, 12, 8, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 1909":
			eol, found = EOL{StandardSupportUntil: time.Date(2021, 5, 11, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 2004":
			eol, found = EOL{StandardSupportUntil: time.Date(2021, 12, 14, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server, Version 20H2":
			eol, found = EOL{StandardSupportUntil: time.Date(2022, 8, 9, 23, 59, 59, 0, time.UTC)}, true
		case "Windows Server 2022":
			eol, found = EOL{StandardSupportUntil: time.Date(2031, 10, 14, 23, 59, 59, 0, time.UTC)}, true
		default:
		}
	case constant.MacOSX, constant.MacOSXServer:
		eol, found = map[string]EOL{
			"10.0":  {Ended: true},
			"10.1":  {Ended: true},
			"10.2":  {Ended: true},
			"10.3":  {Ended: true},
			"10.4":  {Ended: true},
			"10.5":  {Ended: true},
			"10.6":  {Ended: true},
			"10.7":  {Ended: true},
			"10.8":  {Ended: true},
			"10.9":  {Ended: true},
			"10.10": {Ended: true},
			"10.11": {Ended: true},
			"10.12": {Ended: true},
			"10.13": {Ended: true},
			"10.14": {Ended: true},
			"10.15": {Ended: true},
		}[majorDotMinor(release)]
	case constant.MacOS, constant.MacOSServer:
		eol, found = map[string]EOL{
			"11": {},
			"12": {},
			"13": {},
			"14": {},
		}[major(release)]
	}
	return
}

func major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func majorDotMinor(osVer string) (majorDotMinor string) {
	ss := strings.SplitN(osVer, ".", 3)
	if len(ss) == 1 {
		return osVer
	}
	return fmt.Sprintf("%s.%s", ss[0], ss[1])
}

func getAmazonLinuxVersion(osRelease string) string {
	switch s := strings.Fields(osRelease)[0]; major(s) {
	case "1":
		return "1"
	case "2":
		return "2"
	case "2022":
		return "2022"
	case "2023":
		return "2023"
	case "2025":
		return "2025"
	case "2027":
		return "2027"
	case "2029":
		return "2029"
	default:
		if _, err := time.Parse("2006.01", s); err == nil {
			return "1"
		}
		return "unknown"
	}
}
