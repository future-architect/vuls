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

package scan

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/alert"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"time"
)

func TestParseDockerPs(t *testing.T) {
	var test = struct {
		in       string
		expected []config.Container
	}{
		`c7ca0992415a romantic_goldberg ubuntu:14.04.5
f570ae647edc agitated_lovelace centos:latest`,
		[]config.Container{
			{
				ContainerID: "c7ca0992415a",
				Name:        "romantic_goldberg",
				Image:       "ubuntu:14.04.5",
			},
			{
				ContainerID: "f570ae647edc",
				Name:        "agitated_lovelace",
				Image:       "centos:latest",
			},
		},
	}

	r := newRHEL(config.ServerInfo{})
	actual, err := r.parseDockerPs(test.in)
	if err != nil {
		t.Errorf("Error occurred. in: %s, err: %s", test.in, err)
		return
	}
	for i, e := range test.expected {
		if !reflect.DeepEqual(e, actual[i]) {
			t.Errorf("expected %v, actual %v", e, actual[i])
		}
	}
}

func TestParseLxdPs(t *testing.T) {
	var test = struct {
		in       string
		expected []config.Container
	}{
		`+-------+
| NAME  |
+-------+
| test1 |
+-------+
| test2 |
+-------+`,
		[]config.Container{
			{
				ContainerID: "test1",
				Name:        "test1",
			},
			{
				ContainerID: "test2",
				Name:        "test2",
			},
		},
	}

	r := newRHEL(config.ServerInfo{})
	actual, err := r.parseLxdPs(test.in)
	if err != nil {
		t.Errorf("Error occurred. in: %s, err: %s", test.in, err)
		return
	}
	for i, e := range test.expected {
		if !reflect.DeepEqual(e, actual[i]) {
			t.Errorf("expected %v, actual %v", e, actual[i])
		}
	}
}

func TestParseIp(t *testing.T) {

	var test = struct {
		in        string
		expected4 []string
		expected6 []string
	}{
		in: `1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN \    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
1: lo    inet 127.0.0.1/8 scope host lo
1: lo    inet6 ::1/128 scope host \       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\    link/ether 52:54:00:2a:86:4c brd ff:ff:ff:ff:ff:ff
2: eth0    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0
2: eth0    inet6 fe80::5054:ff:fe2a:864c/64 scope link \       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000\    link/ether 08:00:27:36:76:60 brd ff:ff:ff:ff:ff:ff
3: eth1    inet 192.168.33.11/24 brd 192.168.33.255 scope global eth1
3: eth1    inet6 2001:db8::68/64 scope link \       valid_lft forever preferred_lft forever `,
		expected4: []string{"10.0.2.15", "192.168.33.11"},
		expected6: []string{"2001:db8::68"},
	}

	r := newRHEL(config.ServerInfo{})
	actual4, actual6 := r.parseIP(test.in)
	if !reflect.DeepEqual(test.expected4, actual4) {
		t.Errorf("expected %v, actual %v", test.expected4, actual4)
	}
	if !reflect.DeepEqual(test.expected6, actual6) {
		t.Errorf("expected %v, actual %v", test.expected6, actual6)
	}
}

func TestIsAwsInstanceID(t *testing.T) {
	var tests = []struct {
		in       string
		expected bool
	}{
		{"i-1234567a", true},
		{"i-1234567890abcdef0", true},
		{"i-1234567890abcdef0000000", true},
		{"e-1234567890abcdef0", false},
		{"i-1234567890abcdef0 foo bar", false},
		{"no data", false},
	}

	r := newAmazon(config.ServerInfo{})
	for _, tt := range tests {
		actual := r.isAwsInstanceID(tt.in)
		if tt.expected != actual {
			t.Errorf("expected %t, actual %t, str: %s", tt.expected, actual, tt.in)
		}
	}
}

func TestParseSystemctlStatus(t *testing.T) {
	var tests = []struct {
		in  string
		out string
	}{
		{
			in: `● NetworkManager.service - Network Manager
   Loaded: loaded (/usr/lib/systemd/system/NetworkManager.service; enabled; vendor preset: enabled)
   Active: active (running) since Wed 2018-01-10 17:15:39 JST; 2 months 10 days ago
     Docs: man:NetworkManager(8)
 Main PID: 437 (NetworkManager)
   Memory: 424.0K
   CGroup: /system.slice/NetworkManager.service
           ├─437 /usr/sbin/NetworkManager --no-daemon
           └─572 /sbin/dhclient -d -q -sf /usr/libexec/nm-dhcp-helper -pf /var/run/dhclient-ens160.pid -lf /var/lib/NetworkManager/dhclient-241ed966-e1c7-4d5c-a6a0-8a6dba457277-ens160.lease -cf /var/lib/NetworkManager/dhclient-ens160.conf ens160`,
			out: "NetworkManager.service",
		},
		{
			in:  `Failed to get unit for PID 700: PID 700 does not belong to any loaded unit.`,
			out: "",
		},
	}

	r := newCentOS(config.ServerInfo{})
	for _, tt := range tests {
		actual := r.parseSystemctlStatus(tt.in)
		if tt.out != actual {
			t.Errorf("expected %v, actual %v", tt.out, actual)
		}
	}
}

func TestContentConvertVinfo(t *testing.T) {

	var test = struct {
		in1      *base
		in2      string
		in3      WpStatus
		expected []models.VulnInfo
	}{
		in1: &base{osPackages: osPackages{Packages: models.Packages{}, VulnInfos: models.VulnInfos{}}},
		in2: "{\"twentyfifteen\":{\"friendly_name\":\"Twenty Fifteen\"" +
			",\"latest_version\":\"2.3\",\"last_updated\":\"2019-" +
			"01-09T00:00:00.000Z\",\"popular\":true,\"vulnerabili" +
			"ties\":[{\"id\":7965,\"title\":\"Twenty Fifteen Them" +
			"e <= 1.1 - DOM Cross-Site Scripting (XSS)\",\"create" +
			"d_at\":\"2015-05-06T17:22:10.000Z\",\"updated_at\":\"" +
			"2015-05-15T13:49:28.000Z\",\"published_date\":\"2015" +
			"-05-06T00:00:00.000Z\",\"vuln_type\":\"XSS\",\"refer" +
			"ences\":{\"url\":[\"https://blog.sucuri.net/2015/05/" +
			"jetpack-and-twentyfifteen-vulnerable-to-dom-based-xs" +
			"s-millions-of-wordpress-websites-affected-millions-o" +
			"f-wordpress-websites-affected.html\",\"http://packet" +
			"stormsecurity.com/files/131802/\",\"http://seclists." +
			"org/fulldisclosure/2015/May/41\"],\"cve\":[\"2015-34" +
			"29\"]},\"fixed_in\":\"1.2\"}]}}",
		in3: WpStatus{Name: "twentyfifteen", Status: "inactive", Update: "available", Version: "1.1"},
		expected: []models.VulnInfo{
			{
				CveID:       "CVE-2015-3429",
				Confidences: models.Confidences{},
				AffectedPackages: models.PackageStatuses{
					models.PackageStatus{
						Name:        "",
						NotFixedYet: false,
						FixState:    "",
					},
				},
				DistroAdvisories: []models.DistroAdvisory{},
				CpeURIs:          []string{},
				CveContents: models.NewCveContents(
					models.CveContent{
						Type:          "",
						CveID:         "CVE-2015-3429",
						Title:         "Twenty Fifteen Theme <= 1.1 - DOM Cross-Site Scripting (XSS)",
						Summary:       "",
						Cvss2Score:    0.000000,
						Cvss2Vector:   "",
						Cvss2Severity: "",
						Cvss3Score:    0.000000,
						Cvss3Vector:   "",
						Cvss3Severity: "",
						SourceLink:    "",
						Cpes:          []models.Cpe{},
						References:    models.References{},
						CweIDs:        []string{},
						Published:     time.Time{},
						LastModified:  time.Time{},
						Mitigation:    "",
						Optional:      map[string]string{},
					},
				),
				Exploits: []models.Exploit{},
				AlertDict: models.AlertDict{
					Ja: []alert.Alert{},
					En: []alert.Alert{},
				},
			},
		},
	}
	actual, _ := contentConvertVinfo(test.in1, test.in2, test.in3)
	if !reflect.DeepEqual(test.expected, actual) {
		t.Errorf("expected %v, actual %v", test.expected, actual)
	}

}

func TestCoreConvertVinfo(t *testing.T) {

	var test = struct {
		in       string
		expected []models.VulnInfo
	}{
		in: "{\"4.9.4\":{\"release_date\":\"2018-02-06\",\"changelog_url\"" +
			":\"https://codex.wordpress.org/Version_4.9.4\",\"status\"" +
			":\"insecure\",\"vulnerabilities\":[{\"id\":9021,\"title\"" +
			":\"WordPress <= 4.9.4 - Application Denial of Service (Do" +
			"S) (unpatched)\",\"created_at\":\"2018-02-05T16:50:40.000" +
			"Z\",\"updated_at\":\"2018-08-29T19:13:04.000Z\",\"publish" +
			"ed_date\":\"2018-02-05T00:00:00.000Z\",\"vuln_type\":\"DO" +
			"S\",\"references\":{\"url\":[\"https://baraktawily.blogsp" +
			"ot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html\"" +
			",\"https://github.com/quitten/doser.py\",\"https://thehac" +
			"kernews.com/2018/02/wordpress-dos-exploit.html\"],\"cve\"" +
			":[\"2018-6389\"]},\"fixed_in\":null}]}}",
		expected: []models.VulnInfo{
			{
				CveID:       "CVE-2018-6389",
				Confidences: models.Confidences{},
				AffectedPackages: models.PackageStatuses{
					models.PackageStatus{
						Name:        "",
						NotFixedYet: true,
						FixState:    "",
					},
				},
				DistroAdvisories: []models.DistroAdvisory{},
				CpeURIs:          []string{},
				CveContents: models.NewCveContents(
					models.CveContent{
						Type:          "",
						CveID:         "CVE-2018-6389",
						Title:         "WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)",
						Summary:       "",
						Cvss2Score:    0.000000,
						Cvss2Vector:   "",
						Cvss2Severity: "",
						Cvss3Score:    0.000000,
						Cvss3Vector:   "",
						Cvss3Severity: "",
						SourceLink:    "",
						Cpes:          []models.Cpe{},
						References:    models.References{},
						CweIDs:        []string{},
						Published:     time.Time{},
						LastModified:  time.Time{},
						Mitigation:    "",
						Optional:      map[string]string{},
					},
				),
				Exploits: []models.Exploit{},
				AlertDict: models.AlertDict{
					Ja: []alert.Alert{},
					En: []alert.Alert{},
				},
			},
		},
	}
	actual, _ := coreConvertVinfo(test.in)
	if !reflect.DeepEqual(test.expected, actual) {
		t.Errorf("expected %v, actual %v", test.expected, actual)
	}

}
