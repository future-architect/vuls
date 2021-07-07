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
		rel := "2"
		if isAmazonLinux1(release) {
			rel = "1"
		}
		eol, found = map[string]EOL{
			"1": {StandardSupportUntil: time.Date(2023, 6, 30, 23, 59, 59, 0, time.UTC)},
			"2": {},
		}[rel]
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
			},
			"8": {
				StandardSupportUntil: time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC),
			},
		}[major(release)]
	case constant.CentOS:
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
	case constant.Rocky:
		eol, found = map[string]EOL{
			"8": {StandardSupportUntil: time.Date(2029, 5, 31, 23, 59, 59, 0, time.UTC)},
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
				ExtendedSupportUntil: time.Date(2024, 3, 1, 23, 59, 59, 0, time.UTC),
			},
			"7": {
				StandardSupportUntil: time.Date(2024, 7, 1, 23, 59, 59, 0, time.UTC),
			},
			"8": {
				StandardSupportUntil: time.Date(2029, 7, 1, 23, 59, 59, 0, time.UTC),
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
		}[major(release)]
	case constant.Raspbian:
		// Not found
		eol, found = map[string]EOL{}[major(release)]
	case constant.Ubuntu:
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
			"20.10": {
				StandardSupportUntil: time.Date(2021, 7, 22, 23, 59, 59, 0, time.UTC),
			},
			"21.04": {
				StandardSupportUntil: time.Date(2022, 1, 22, 23, 59, 59, 0, time.UTC),
			},
			"21.10": {
				StandardSupportUntil: time.Date(2022, 7, 1, 23, 59, 59, 0, time.UTC),
			},
		}[release]
	case constant.SUSEEnterpriseServer:
		//TODO
	case constant.Alpine:
		// https://github.com/aquasecurity/trivy/blob/master/pkg/detector/ospkg/alpine/alpine.go#L19
		// https://wiki.alpinelinux.org/wiki/Alpine_Linux:Releases
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
		}[majorDotMinor(release)]
	case constant.FreeBSD:
		// https://www.freebsd.org/security/
		eol, found = map[string]EOL{
			"7":  {Ended: true},
			"8":  {Ended: true},
			"9":  {Ended: true},
			"10": {Ended: true},
			"11": {StandardSupportUntil: time.Date(2021, 9, 30, 23, 59, 59, 0, time.UTC)},
			"12": {StandardSupportUntil: time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC)},
			"13": {StandardSupportUntil: time.Date(2026, 1, 31, 23, 59, 59, 0, time.UTC)},
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

func isAmazonLinux1(osRelease string) bool {
	return len(strings.Fields(osRelease)) == 1
}
