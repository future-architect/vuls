package config

import (
	"testing"
	"time"

	. "github.com/future-architect/vuls/constant"
)

func TestEOL_IsStandardSupportEnded(t *testing.T) {
	type fields struct {
		family  string
		release string
	}
	tests := []struct {
		name     string
		fields   fields
		now      time.Time
		found    bool
		stdEnded bool
		extEnded bool
	}{
		// Amazon Linux
		{
			name:     "amazon linux 1 supported",
			fields:   fields{family: Amazon, release: "2018.03"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "amazon linux 1 eol on 2023-12-31",
			fields:   fields{family: Amazon, release: "2018.03"},
			now:      time.Date(2024, 1, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "amazon linux 2 supported",
			fields:   fields{family: Amazon, release: "2 (Karoo)"},
			now:      time.Date(2023, 7, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "amazon linux 2022 supported",
			fields:   fields{family: Amazon, release: "2022 (Amazon Linux)"},
			now:      time.Date(2023, 7, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "amazon linux 2023 supported",
			fields:   fields{family: Amazon, release: "2023"},
			now:      time.Date(2023, 7, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "amazon linux 2031 not found",
			fields:   fields{family: Amazon, release: "2031"},
			now:      time.Date(2023, 7, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		//RHEL
		{
			name:     "RHEL6 eol",
			fields:   fields{family: RedHat, release: "6"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: false,
			found:    true,
		},
		{
			name:     "RHEL7 supported",
			fields:   fields{family: RedHat, release: "7"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "RHEL8 supported",
			fields:   fields{family: RedHat, release: "8"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "RHEL9 supported",
			fields:   fields{family: RedHat, release: "9"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "RHEL10 not found",
			fields:   fields{family: RedHat, release: "10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		//CentOS
		{
			name:     "CentOS 6 eol",
			fields:   fields{family: CentOS, release: "6"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "CentOS 7 supported",
			fields:   fields{family: CentOS, release: "7"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "CentOS 8 supported",
			fields:   fields{family: CentOS, release: "8"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "CentOS stream8 supported",
			fields:   fields{family: CentOS, release: "stream8"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "CentOS stream9 supported",
			fields:   fields{family: CentOS, release: "stream9"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "CentOS stream10 Not Found",
			fields:   fields{family: CentOS, release: "stream10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		// Alma
		{
			name:     "Alma Linux 8 supported",
			fields:   fields{family: Alma, release: "8"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alma Linux 9 supported",
			fields:   fields{family: Alma, release: "9"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alma Linux 10 Not Found",
			fields:   fields{family: Alma, release: "10"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		// Rocky
		{
			name:     "Rocky Linux 8 supported",
			fields:   fields{family: Rocky, release: "8"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Rocky Linux 9 supported",
			fields:   fields{family: Rocky, release: "9"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Rocky Linux 10 Not Found",
			fields:   fields{family: Rocky, release: "10"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		//Oracle
		{
			name:     "Oracle Linux 6 eol",
			fields:   fields{family: Oracle, release: "6"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Oracle Linux 7 supported",
			fields:   fields{family: Oracle, release: "7"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Oracle Linux 8 supported",
			fields:   fields{family: Oracle, release: "8"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Oracle Linux 9 supported",
			fields:   fields{family: Oracle, release: "9"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Oracle Linux 10 not found",
			fields:   fields{family: Oracle, release: "10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		//Ubuntu
		{
			name:     "Ubuntu 5.10 not found",
			fields:   fields{family: Ubuntu, release: "5.10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			found:    false,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 14.04 eol",
			fields:   fields{family: Ubuntu, release: "14.04"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Ubuntu 14.10 eol",
			fields:   fields{family: Ubuntu, release: "14.10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Ubuntu 16.04 supported",
			fields:   fields{family: Ubuntu, release: "18.04"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Ubuntu 18.04 supported",
			fields:   fields{family: Ubuntu, release: "18.04"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Ubuntu 18.04 ext supported",
			fields:   fields{family: Ubuntu, release: "18.04"},
			now:      time.Date(2025, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Ubuntu 20.04 supported",
			fields:   fields{family: Ubuntu, release: "20.04"},
			now:      time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 20.04 ext supported",
			fields:   fields{family: Ubuntu, release: "20.04"},
			now:      time.Date(2025, 5, 1, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: true,
			extEnded: false,
		},
		{
			name:     "Ubuntu 20.10 supported",
			fields:   fields{family: Ubuntu, release: "20.10"},
			now:      time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 21.04 supported",
			fields:   fields{family: Ubuntu, release: "21.04"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 21.10 supported",
			fields:   fields{family: Ubuntu, release: "21.10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 22.04 supported",
			fields:   fields{family: Ubuntu, release: "22.04"},
			now:      time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 22.10 supported",
			fields:   fields{family: Ubuntu, release: "22.10"},
			now:      time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 23.04 supported",
			fields:   fields{family: Ubuntu, release: "23.04"},
			now:      time.Date(2023, 3, 16, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 23.10 supported",
			fields:   fields{family: Ubuntu, release: "23.10"},
			now:      time.Date(2024, 7, 31, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		{
			name:     "Ubuntu 24.04 supported",
			fields:   fields{family: Ubuntu, release: "24.04"},
			now:      time.Date(2029, 6, 30, 23, 59, 59, 0, time.UTC),
			found:    true,
			stdEnded: false,
			extEnded: false,
		},
		//Debian
		{
			name:     "Debian 8 supported",
			fields:   fields{family: Debian, release: "8"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Debian 9 supported",
			fields:   fields{family: Debian, release: "9"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Debian 10 supported",
			fields:   fields{family: Debian, release: "10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Debian 11 supported",
			fields:   fields{family: Debian, release: "11"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Debian 12 supported",
			fields:   fields{family: Debian, release: "12"},
			now:      time.Date(2023, 6, 10, 0, 0, 0, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Debian 13 is not supported yet",
			fields:   fields{family: Debian, release: "13"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		//alpine
		{
			name:     "alpine 3.10 supported",
			fields:   fields{family: Alpine, release: "3.10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.11 supported",
			fields:   fields{family: Alpine, release: "3.11"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.12 supported",
			fields:   fields{family: Alpine, release: "3.12"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.9 eol",
			fields:   fields{family: Alpine, release: "3.9"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Alpine 3.14 supported",
			fields:   fields{family: Alpine, release: "3.14"},
			now:      time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.15 supported",
			fields:   fields{family: Alpine, release: "3.15"},
			now:      time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.16 supported",
			fields:   fields{family: Alpine, release: "3.16"},
			now:      time.Date(2024, 5, 23, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.17 supported",
			fields:   fields{family: Alpine, release: "3.17"},
			now:      time.Date(2022, 1, 14, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.18 supported",
			fields:   fields{family: Alpine, release: "3.18"},
			now:      time.Date(2025, 5, 9, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Alpine 3.19 not found",
			fields:   fields{family: Alpine, release: "3.19"},
			now:      time.Date(2022, 1, 14, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		// freebsd
		{
			name:     "freebsd 10 eol",
			fields:   fields{family: FreeBSD, release: "10"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "freebsd 11 supported",
			fields:   fields{family: FreeBSD, release: "11"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "freebsd 11 eol on 2021-9-30",
			fields:   fields{family: FreeBSD, release: "11"},
			now:      time.Date(2021, 10, 1, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "freebsd 12 supported",
			fields:   fields{family: FreeBSD, release: "12"},
			now:      time.Date(2021, 1, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "freebsd 13 supported",
			fields:   fields{family: FreeBSD, release: "13"},
			now:      time.Date(2021, 7, 2, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "freebsd 14 supported",
			fields:   fields{family: FreeBSD, release: "14"},
			now:      time.Date(2028, 11, 21, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		// Fedora
		{
			name:     "Fedora 32 supported",
			fields:   fields{family: Fedora, release: "32"},
			now:      time.Date(2021, 5, 24, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 32 eol since 2021-5-25",
			fields:   fields{family: Fedora, release: "32"},
			now:      time.Date(2021, 5, 25, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 33 supported",
			fields:   fields{family: Fedora, release: "33"},
			now:      time.Date(2021, 11, 29, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 33 eol since 2021-11-30",
			fields:   fields{family: Fedora, release: "32"},
			now:      time.Date(2021, 11, 30, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 34 supported",
			fields:   fields{family: Fedora, release: "34"},
			now:      time.Date(2022, 6, 6, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 34 eol since 2022-6-7",
			fields:   fields{family: Fedora, release: "34"},
			now:      time.Date(2022, 6, 7, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 35 supported",
			fields:   fields{family: Fedora, release: "35"},
			now:      time.Date(2022, 12, 12, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 35 eol since 2022-12-13",
			fields:   fields{family: Fedora, release: "35"},
			now:      time.Date(2022, 12, 13, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 36 supported",
			fields:   fields{family: Fedora, release: "36"},
			now:      time.Date(2023, 5, 16, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 36 eol since 2023-05-17",
			fields:   fields{family: Fedora, release: "36"},
			now:      time.Date(2023, 5, 17, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 37 supported",
			fields:   fields{family: Fedora, release: "37"},
			now:      time.Date(2023, 12, 15, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 37 eol since 2023-12-16",
			fields:   fields{family: Fedora, release: "37"},
			now:      time.Date(2023, 12, 16, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 38 supported",
			fields:   fields{family: Fedora, release: "38"},
			now:      time.Date(2024, 5, 14, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 38 eol since 2024-05-15",
			fields:   fields{family: Fedora, release: "38"},
			now:      time.Date(2024, 5, 15, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 39 supported",
			fields:   fields{family: Fedora, release: "39"},
			now:      time.Date(2024, 11, 12, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Fedora 39 eol since 2024-11-13",
			fields:   fields{family: Fedora, release: "39"},
			now:      time.Date(2024, 11, 13, 0, 0, 0, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Fedora 40 not found",
			fields:   fields{family: Fedora, release: "40"},
			now:      time.Date(2024, 11, 12, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    false,
		},
		{
			name:     "Windows 10 EOL",
			fields:   fields{family: Windows, release: "Windows 10 for x64-based Systems"},
			now:      time.Date(2022, 12, 8, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "Windows 10 Version 22H2 supported",
			fields:   fields{family: Windows, release: "Windows 10 Version 22H2 for x64-based Systems"},
			now:      time.Date(2022, 12, 8, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
		{
			name:     "Mac OS X 10.15 EOL",
			fields:   fields{family: MacOSX, release: "10.15.7"},
			now:      time.Date(2023, 7, 25, 23, 59, 59, 0, time.UTC),
			stdEnded: true,
			extEnded: true,
			found:    true,
		},
		{
			name:     "macOS 13.4.1 supported",
			fields:   fields{family: MacOS, release: "13.4.1"},
			now:      time.Date(2023, 7, 25, 23, 59, 59, 0, time.UTC),
			stdEnded: false,
			extEnded: false,
			found:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eol, found := GetEOL(tt.fields.family, tt.fields.release)
			if found != tt.found {
				t.Errorf("GetEOL.found = %v, want %v", found, tt.found)
			}
			if found {
				if got := eol.IsStandardSupportEnded(tt.now); got != tt.stdEnded {
					t.Errorf("EOL.IsStandardSupportEnded() = %v, want %v", got, tt.stdEnded)
				}
				if got := eol.IsExtendedSuppportEnded(tt.now); got != tt.extEnded {
					t.Errorf("EOL.IsExtendedSupportEnded() = %v, want %v", got, tt.extEnded)
				}
			}
		})
	}
}

func Test_majorDotMinor(t *testing.T) {
	type args struct {
		osVer string
	}
	tests := []struct {
		name              string
		args              args
		wantMajorDotMinor string
	}{
		{
			name: "empty",
			args: args{
				osVer: "",
			},
			wantMajorDotMinor: "",
		},
		{
			name: "major",
			args: args{
				osVer: "3",
			},
			wantMajorDotMinor: "3",
		},
		{
			name: "major dot minor",
			args: args{
				osVer: "3.1",
			},
			wantMajorDotMinor: "3.1",
		},
		{
			name: "major dot minor dot release",
			args: args{
				osVer: "3.1.4",
			},
			wantMajorDotMinor: "3.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMajorDotMinor := majorDotMinor(tt.args.osVer); gotMajorDotMinor != tt.wantMajorDotMinor {
				t.Errorf("majorDotMinor() = %v, want %v", gotMajorDotMinor, tt.wantMajorDotMinor)
			}
		})
	}
}

func Test_getAmazonLinuxVersion(t *testing.T) {
	tests := []struct {
		release string
		want    string
	}{
		{
			release: "2017.09",
			want:    "1",
		},
		{
			release: "2018.03",
			want:    "1",
		},
		{
			release: "1",
			want:    "1",
		},
		{
			release: "2",
			want:    "2",
		},
		{
			release: "2022",
			want:    "2022",
		},
		{
			release: "2023",
			want:    "2023",
		},
		{
			release: "2023.3.20240312",
			want:    "2023",
		},
		{
			release: "2025",
			want:    "2025",
		},
		{
			release: "2027",
			want:    "2027",
		},
		{
			release: "2029",
			want:    "2029",
		},
		{
			release: "2031",
			want:    "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.release, func(t *testing.T) {
			if got := getAmazonLinuxVersion(tt.release); got != tt.want {
				t.Errorf("getAmazonLinuxVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
