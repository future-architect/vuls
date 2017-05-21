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

var m = CveContent{
	Type:        RedHat,
	CveID:       "CVE-2017-0001",
	Title:       "title",
	Summary:     "summary",
	Severity:    "High",
	Cvss2Score:  8.0,
	Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
	Cvss3Score:  9.0,
	Cvss3Vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
}

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

func TestCvss2Scores(t *testing.T) {
	var tests = []struct {
		in  CveContents
		out []CveContentCvss2
	}{
		{
			in: CveContents{
				JVN: {
					Type:        JVN,
					Severity:    "HIGH",
					Cvss2Score:  8.2,
					Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
				},
				RedHat: {
					Type:        RedHat,
					Severity:    "HIGH",
					Cvss2Score:  8.0,
					Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
				},
				NVD: {
					Type:        NVD,
					Cvss2Score:  8.1,
					Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					// Severity is NIOT included in NVD
				},
			},
			out: []CveContentCvss2{
				{
					Type: NVD,
					Value: Cvss2{
						Score:    8.1,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
				{
					Type: RedHat,
					Value: Cvss2{
						Score:    8.0,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
				{
					Type: JVN,
					Value: Cvss2{
						Score:    8.2,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
			},
		},
		// Empty
		{
			in:  CveContents{},
			out: nil,
		},
	}
	for _, tt := range tests {
		actual := tt.in.Cvss2Scores()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestMaxCvss2Scores(t *testing.T) {
	var tests = []struct {
		in  CveContents
		out CveContentCvss2
	}{
		{
			in: CveContents{
				JVN: {
					Type:        JVN,
					Severity:    "HIGH",
					Cvss2Score:  8.2,
					Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
				},
				RedHat: {
					Type:        RedHat,
					Severity:    "HIGH",
					Cvss2Score:  8.0,
					Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
				},
				NVD: {
					Type:        NVD,
					Cvss2Score:  8.1,
					Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					// Severity is NIOT included in NVD
				},
			},
			out: CveContentCvss2{
				Type: JVN,
				Value: Cvss2{
					Score:    8.2,
					Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					Severity: "HIGH",
				},
			},
		},
		// Empty
		{
			in: CveContents{},
			out: CveContentCvss2{
				Type: Unknown,
				Value: Cvss2{
					Score:    0.0,
					Vector:   "",
					Severity: "",
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.MaxCvss2Score()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestCvss3Scores(t *testing.T) {
	var tests = []struct {
		in  CveContents
		out []CveContentCvss3
	}{
		{
			in: CveContents{
				RedHat: {
					Type:        RedHat,
					Severity:    "HIGH",
					Cvss3Score:  8.0,
					Cvss3Vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
				},
				NVD: {
					Type:        NVD,
					Cvss3Score:  8.1,
					Cvss3Vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
					// Severity is NIOT included in NVD
				},
			},
			out: []CveContentCvss3{
				{
					Type: RedHat,
					Value: Cvss3{
						Score:    8.0,
						Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
						Severity: "HIGH",
					},
				},
			},
		},
		// Empty
		{
			in:  CveContents{},
			out: nil,
		},
	}
	for _, tt := range tests {
		actual := tt.in.Cvss3Scores()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestMaxCvss3Scores(t *testing.T) {
	var tests = []struct {
		in  CveContents
		out CveContentCvss3
	}{
		{
			in: CveContents{
				RedHat: {
					Type:        RedHat,
					Severity:    "HIGH",
					Cvss3Score:  8.0,
					Cvss3Vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
				},
			},
			out: CveContentCvss3{
				Type: RedHat,
				Value: Cvss3{
					Score:    8.0,
					Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
					Severity: "HIGH",
				},
			},
		},
		// Empty
		{
			in: CveContents{},
			out: CveContentCvss3{
				Type: Unknown,
				Value: Cvss3{
					Score:    0.0,
					Vector:   "",
					Severity: "",
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.MaxCvss3Score()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestFormatMaxCvssScore(t *testing.T) {
	var tests = []struct {
		in  CveContents
		out string
	}{
		{
			in: CveContents{
				JVN: {
					Type:       JVN,
					Severity:   "HIGH",
					Cvss2Score: 8.3,
				},
				RedHat: {
					Type:       RedHat,
					Severity:   "HIGH",
					Cvss3Score: 8.0,
				},
				NVD: {
					Type:       NVD,
					Cvss2Score: 8.1,
					// Severity is NIOT included in NVD
				},
			},
			out: "8.3 HIGH (jvn)",
		},
		{
			in: CveContents{
				JVN: {
					Type:       JVN,
					Severity:   "HIGH",
					Cvss2Score: 8.3,
				},
				RedHat: {
					Type:       RedHat,
					Severity:   "HIGH",
					Cvss2Score: 8.0,
					Cvss3Score: 9.9,
				},
				NVD: {
					Type:       NVD,
					Cvss2Score: 8.1,
				},
			},
			out: "9.9 HIGH (redhat)",
		},
	}
	for _, tt := range tests {
		actual := tt.in.FormatMaxCvssScore()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestTitles(t *testing.T) {
	type in struct {
		lang string
		cont CveContents
	}
	var tests = []struct {
		in  in
		out []CveContentStr
	}{
		// lang: ja
		{
			in: in{
				lang: "ja",
				cont: CveContents{
					JVN: {
						Type:  JVN,
						Title: "Title1",
					},
					RedHat: {
						Type:    RedHat,
						Summary: "Summary RedHat",
					},
					NVD: {
						Type:    NVD,
						Summary: "Summary NVD",
						// Severity is NIOT included in NVD
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  JVN,
					Value: "Title1",
				},
				{
					Type:  NVD,
					Value: "Summary NVD",
				},
				{
					Type:  RedHat,
					Value: "Summary RedHat",
				},
			},
		},
		// lang: en
		{
			in: in{
				lang: "en",
				cont: CveContents{
					JVN: {
						Type:  JVN,
						Title: "Title1",
					},
					RedHat: {
						Type:    RedHat,
						Summary: "Summary RedHat",
					},
					NVD: {
						Type:    NVD,
						Summary: "Summary NVD",
						// Severity is NIOT included in NVD
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  NVD,
					Value: "Summary NVD",
				},
				{
					Type:  RedHat,
					Value: "Summary RedHat",
				},
			},
		},
		// lang: empty
		{
			in: in{
				lang: "en",
				cont: CveContents{},
			},
			out: []CveContentStr{
				{
					Type:  Unknown,
					Value: "-",
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.cont.Titles(tt.in.lang, "redhat")
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestSummaries(t *testing.T) {
	type in struct {
		lang string
		cont CveContents
	}
	var tests = []struct {
		in  in
		out []CveContentStr
	}{
		// lang: ja
		{
			in: in{
				lang: "ja",
				cont: CveContents{
					JVN: {
						Type:    JVN,
						Title:   "Title JVN",
						Summary: "Summary JVN",
					},
					RedHat: {
						Type:    RedHat,
						Summary: "Summary RedHat",
					},
					NVD: {
						Type:    NVD,
						Summary: "Summary NVD",
						// Severity is NIOT included in NVD
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  JVN,
					Value: "Title JVN\nSummary JVN",
				},
				{
					Type:  NVD,
					Value: "Summary NVD",
				},
				{
					Type:  RedHat,
					Value: "Summary RedHat",
				},
			},
		},
		// lang: en
		{
			in: in{
				lang: "en",
				cont: CveContents{
					JVN: {
						Type:    JVN,
						Title:   "Title JVN",
						Summary: "Summary JVN",
					},
					RedHat: {
						Type:    RedHat,
						Summary: "Summary RedHat",
					},
					NVD: {
						Type:    NVD,
						Summary: "Summary NVD",
						// Severity is NIOT included in NVD
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  NVD,
					Value: "Summary NVD",
				},
				{
					Type:  RedHat,
					Value: "Summary RedHat",
				},
			},
		},
		// lang: empty
		{
			in: in{
				lang: "en",
				cont: CveContents{},
			},
			out: []CveContentStr{
				{
					Type:  Unknown,
					Value: "-",
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.cont.Summaries(tt.in.lang, "redhat")
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
		cont   CveContents
	}
	var tests = []struct {
		in  in
		out CveContentStr
	}{
		{
			in: in{
				family: "redhat",
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
			out: CveContentStr{
				Type:  RedHat,
				Value: "https://access.redhat.com/security/cve/CVE-2017-6074",
			},
		},
		{
			in: in{
				family: "ubuntu",
				cont: CveContents{
					RedHat: {
						Type:       RedHat,
						SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
					},
				},
			},
			out: CveContentStr{
				Type:  Ubuntu,
				Value: "",
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.cont.VendorLink(tt.in.family)
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}
