package reporter

import (
	"sort"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
)

func TestSyslogWriterEncodeSyslog(t *testing.T) {
	var tests = []struct {
		result           models.ScanResult
		expectedMessages []string
	}{
		{
			result: models.ScanResult{
				ScannedAt:  time.Date(2018, 6, 13, 16, 10, 0, 0, time.UTC),
				ServerName: "teste01",
				Family:     "ubuntu",
				Release:    "16.04",
				IPv4Addrs:  []string{"192.168.0.1", "10.0.2.15"},
				ScannedCves: models.VulnInfos{
					"CVE-2017-0001": models.VulnInfo{
						AffectedPackages: models.PackageFixStatuses{
							models.PackageFixStatus{Name: "pkg1"},
							models.PackageFixStatus{Name: "pkg2"},
						},
					},
					"CVE-2017-0002": models.VulnInfo{
						AffectedPackages: models.PackageFixStatuses{
							models.PackageFixStatus{Name: "pkg3"},
							models.PackageFixStatus{Name: "pkg4"},
						},
						CveContents: models.CveContents{
							models.Nvd: models.CveContent{
								Cvss2Score:    5.0,
								Cvss2Vector:   "AV:L/AC:L/Au:N/C:N/I:N/A:C",
								Cvss2Severity: "MEDIUM",
								CweIDs:        []string{"CWE-20"},
								Cvss3Score:    9.8,
								Cvss3Vector:   "AV:L/AC:L/Au:N/C:N/I:N/A:C",
								Cvss3Severity: "HIGH",
							},
						},
					},
				},
			},
			expectedMessages: []string{
				`scanned_at="2018-06-13 16:10:00 +0000 UTC" server_name="teste01" os_family="ubuntu" os_release="16.04" ipv4_addr="192.168.0.1,10.0.2.15" ipv6_addr="" packages="pkg1,pkg2" cve_id="CVE-2017-0001"`,
				`scanned_at="2018-06-13 16:10:00 +0000 UTC" server_name="teste01" os_family="ubuntu" os_release="16.04" ipv4_addr="192.168.0.1,10.0.2.15" ipv6_addr="" packages="pkg3,pkg4" cve_id="CVE-2017-0002" cvss_score_nvd_v2="5.00" cvss_vector_nvd_v2="AV:L/AC:L/Au:N/C:N/I:N/A:C" cvss_score_nvd_v3="9.80" cvss_vector_nvd_v3="AV:L/AC:L/Au:N/C:N/I:N/A:C" cwe_ids="CWE-20"`,
			},
		},
		// 1
		{
			result: models.ScanResult{
				ScannedAt:  time.Date(2018, 6, 13, 17, 10, 0, 0, time.UTC),
				ServerName: "teste02",
				Family:     "centos",
				Release:    "6",
				IPv6Addrs:  []string{"2001:0DB8::1"},
				ScannedCves: models.VulnInfos{
					"CVE-2017-0003": models.VulnInfo{
						AffectedPackages: models.PackageFixStatuses{
							models.PackageFixStatus{Name: "pkg5"},
						},
						CveContents: models.CveContents{
							models.RedHat: models.CveContent{
								Cvss3Score:    5.0,
								Cvss3Severity: "Medium",
								Cvss3Vector:   "AV:L/AC:L/Au:N/C:N/I:N/A:C",
								CweIDs:        []string{"CWE-284"},
								Title:         "RHSA-2017:0001: pkg5 security update (Important)",
							},
						},
					},
				},
			},
			expectedMessages: []string{
				`scanned_at="2018-06-13 17:10:00 +0000 UTC" server_name="teste02" os_family="centos" os_release="6" ipv4_addr="" ipv6_addr="2001:0DB8::1" packages="pkg5" cve_id="CVE-2017-0003" cvss_score_redhat_v3="5.00" cvss_vector_redhat_v3="AV:L/AC:L/Au:N/C:N/I:N/A:C" title="RHSA-2017:0001: pkg5 security update (Important)"`,
			},
		},
		{
			result: models.ScanResult{
				ScannedAt:   time.Date(2018, 6, 13, 12, 10, 0, 0, time.UTC),
				ServerName:  "teste03",
				Family:      "centos",
				Release:     "7",
				IPv6Addrs:   []string{"2001:0DB8::1"},
				ScannedCves: models.VulnInfos{},
			},
			expectedMessages: []string{
				`scanned_at="2018-06-13 12:10:00 +0000 UTC" server_name="teste03" os_family="centos" os_release="7" ipv4_addr="" ipv6_addr="2001:0DB8::1" message="No CVE-IDs are found"`,
			},
		},
	}

	for i, tt := range tests {
		messages := SyslogWriter{}.encodeSyslog(tt.result)
		if len(messages) != len(tt.expectedMessages) {
			t.Fatalf("test: %d, Message Length: expected %d, actual: %d",
				i, len(tt.expectedMessages), len(messages))
		}

		sort.Slice(messages, func(i, j int) bool {
			return messages[i] < messages[j]
		})

		for j, m := range messages {
			e := tt.expectedMessages[j]
			if e != m {
				t.Errorf("test: %d, Messsage %d: \nexpected %s \nactual   %s", i, j, e, m)
			}
		}
	}
}
