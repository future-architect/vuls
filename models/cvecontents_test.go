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
	"reflect"
	"testing"
)

func TestExcept(t *testing.T) {
	var tests = []struct {
		in  CveContents
		out CveContents
	}{{
		in: CveContents{
			RedHat: {Type: RedHat},
			Ubuntu: {Type: Ubuntu},
			Debian: {Type: Debian},
		},
		out: CveContents{
			RedHat: {Type: RedHat},
		},
	},
	}
	for _, tt := range tests {
		actual := tt.in.Except(Ubuntu, Debian)
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestSourceLinks(t *testing.T) {
	type in struct {
		lang  string
		cveID string
		cont  CveContents
	}
	var tests = []struct {
		in  in
		out []CveContentStr
	}{
		// lang: ja
		{
			in: in{
				lang:  "ja",
				cveID: "CVE-2017-6074",
				cont: CveContents{
					JVN: {
						Type:       JVN,
						SourceLink: "https://jvn.jp/vu/JVNVU93610402/",
					},
					RedHat: {
						Type:       RedHat,
						SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
					},
					NVD: {
						Type:       NVD,
						SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  JVN,
					Value: "https://jvn.jp/vu/JVNVU93610402/",
				},
				{
					Type:  NVD,
					Value: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
				},
				{
					Type:  RedHat,
					Value: "https://access.redhat.com/security/cve/CVE-2017-6074",
				},
			},
		},
		// lang: en
		{
			in: in{
				lang:  "en",
				cveID: "CVE-2017-6074",
				cont: CveContents{
					JVN: {
						Type:       JVN,
						SourceLink: "https://jvn.jp/vu/JVNVU93610402/",
					},
					RedHat: {
						Type:       RedHat,
						SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
					},
					NVD: {
						Type:       NVD,
						SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  NVD,
					Value: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
				},
				{
					Type:  RedHat,
					Value: "https://access.redhat.com/security/cve/CVE-2017-6074",
				},
			},
		},
		// lang: empty
		{
			in: in{
				lang:  "en",
				cveID: "CVE-2017-6074",
				cont:  CveContents{},
			},
			out: []CveContentStr{
				{
					Type:  NVD,
					Value: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.cont.SourceLinks(tt.in.lang, "redhat", tt.in.cveID)
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestVendorLink(t *testing.T) {
	type in struct {
		family string
		vinfo  VulnInfo
	}
	var tests = []struct {
		in  in
		out map[string]string
	}{
		{
			in: in{
				family: "redhat",
				vinfo: VulnInfo{
					CveID: "CVE-2017-6074",
					CveContents: CveContents{
						JVN: {
							Type:       JVN,
							SourceLink: "https://jvn.jp/vu/JVNVU93610402/",
						},
						RedHat: {
							Type:       RedHat,
							SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
						},
						NVD: {
							Type:       NVD,
							SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
						},
					},
				},
			},
			out: map[string]string{
				"RHEL-CVE": "https://access.redhat.com/security/cve/CVE-2017-6074",
			},
		},
		{
			in: in{
				family: "ubuntu",
				vinfo: VulnInfo{
					CveID: "CVE-2017-6074",
					CveContents: CveContents{
						RedHat: {
							Type:       Ubuntu,
							SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
						},
					},
				},
			},
			out: map[string]string{
				"Ubuntu-CVE": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2017-6074",
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.vinfo.VendorLinks(tt.in.family)
		for k := range tt.out {
			if tt.out[k] != actual[k] {
				t.Errorf("\nexpected: %s\n  actual: %s\n", tt.out[k], actual[k])
			}
		}
	}
}
