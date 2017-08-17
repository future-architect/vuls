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

func TestTitles(t *testing.T) {
	type in struct {
		lang string
		cont VulnInfo
	}
	var tests = []struct {
		in  in
		out []CveContentStr
	}{
		// lang: ja
		{
			in: in{
				lang: "ja",
				cont: VulnInfo{
					CveContents: CveContents{
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
				cont: VulnInfo{
					CveContents: CveContents{
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
				cont: VulnInfo{},
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
		cont VulnInfo
	}
	var tests = []struct {
		in  in
		out []CveContentStr
	}{
		// lang: ja
		{
			in: in{
				lang: "ja",
				cont: VulnInfo{
					CveContents: CveContents{
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
				cont: VulnInfo{
					CveContents: CveContents{
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
				cont: VulnInfo{},
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

func TestCountGroupBySeverity(t *testing.T) {
	var tests = []struct {
		in  VulnInfos
		out map[string]int
	}{
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 2.0,
						},
					},
				},
				"CVE-2017-0004": {
					CveID: "CVE-2017-0004",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 5.0,
						},
					},
				},
				"CVE-2017-0005": {
					CveID: "CVE-2017-0005",
				},
			},
			out: map[string]int{
				"High":    1,
				"Medium":  1,
				"Low":     1,
				"Unknown": 1,
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.CountGroupBySeverity()
		for k := range tt.out {
			if tt.out[k] != actual[k] {
				t.Errorf("\nexpected %s: %d\n  actual %d\n",
					k, tt.out[k], actual[k])
			}
		}
	}
}

func TestToSortedSlice(t *testing.T) {
	var tests = []struct {
		in  VulnInfos
		out []VulnInfo
	}{
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss3Score: 7.0,
						},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 7.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss3Score: 8.0,
						},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 7.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss3Score: 8.0,
						},
					},
				},
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss3Score: 7.0,
						},
					},
				},
			},
		},
		// When max scores are the same, sort by CVE-ID
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss3Score: 7.0,
						},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						RedHat: {
							Type:       RedHat,
							Cvss2Score: 7.0,
						},
					},
				},
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						NVD: {
							Type:       NVD,
							Cvss2Score: 6.0,
						},
						RedHat: {
							Type:       RedHat,
							Cvss3Score: 7.0,
						},
					},
				},
			},
		},
		// When there are no cvss scores, sort by severity
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "High",
						},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "Low",
						},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "High",
						},
					},
				},
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Ubuntu: {
							Type:     Ubuntu,
							Severity: "Low",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		actual := tt.in.ToSortedSlice()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, actual)
		}
	}
}

func TestCvss2Scores(t *testing.T) {
	var tests = []struct {
		in  VulnInfo
		out []CveContentCvss
	}{
		{
			in: VulnInfo{
				CveContents: CveContents{
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
			},
			out: []CveContentCvss{
				{
					Type: NVD,
					Value: Cvss{
						Type:     CVSS2,
						Score:    8.1,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
				{
					Type: RedHat,
					Value: Cvss{
						Type:     CVSS2,
						Score:    8.0,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
				{
					Type: JVN,
					Value: Cvss{
						Type:     CVSS2,
						Score:    8.2,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
			},
		},
		// Empty
		{
			in:  VulnInfo{},
			out: nil,
		},
	}
	for i, tt := range tests {
		actual := tt.in.Cvss2Scores()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("[%d] expected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestMaxCvss2Scores(t *testing.T) {
	var tests = []struct {
		in  VulnInfo
		out CveContentCvss
	}{
		{
			in: VulnInfo{
				CveContents: CveContents{
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
			},
			out: CveContentCvss{
				Type: JVN,
				Value: Cvss{
					Type:     CVSS2,
					Score:    8.2,
					Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					Severity: "HIGH",
				},
			},
		},
		// Severity in OVAL
		{
			in: VulnInfo{
				CveContents: CveContents{
					Ubuntu: {
						Type:     Ubuntu,
						Severity: "HIGH",
					},
				},
			},
			out: CveContentCvss{
				Type: Ubuntu,
				Value: Cvss{
					Type:                 CVSS2,
					Score:                8.9,
					CalculatedBySeverity: true,
					Severity:             "HIGH",
				},
			},
		},
		// Empty
		{
			in: VulnInfo{},
			out: CveContentCvss{
				Type: Unknown,
				Value: Cvss{
					Type:     CVSS2,
					Score:    0.0,
					Vector:   "",
					Severity: "",
				},
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.MaxCvss2Score()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("[%d] expected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestCvss3Scores(t *testing.T) {
	var tests = []struct {
		in  VulnInfo
		out []CveContentCvss
	}{
		{
			in: VulnInfo{
				CveContents: CveContents{
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
			},
			out: []CveContentCvss{
				{
					Type: RedHat,
					Value: Cvss{
						Type:     CVSS3,
						Score:    8.0,
						Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
						Severity: "HIGH",
					},
				},
			},
		},
		// Empty
		{
			in:  VulnInfo{},
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
		in  VulnInfo
		out CveContentCvss
	}{
		{
			in: VulnInfo{
				CveContents: CveContents{
					RedHat: {
						Type:        RedHat,
						Severity:    "HIGH",
						Cvss3Score:  8.0,
						Cvss3Vector: "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
					},
				},
			},
			out: CveContentCvss{
				Type: RedHat,
				Value: Cvss{
					Type:     CVSS3,
					Score:    8.0,
					Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
					Severity: "HIGH",
				},
			},
		},
		// Empty
		{
			in: VulnInfo{},
			out: CveContentCvss{
				Type: Unknown,
				Value: Cvss{
					Type:     CVSS3,
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

func TestMaxCvssScores(t *testing.T) {
	var tests = []struct {
		in  VulnInfo
		out CveContentCvss
	}{
		{
			in: VulnInfo{
				CveContents: CveContents{
					NVD: {
						Type:       NVD,
						Cvss3Score: 7.0,
					},
					RedHat: {
						Type:       RedHat,
						Cvss2Score: 8.0,
					},
				},
			},
			out: CveContentCvss{
				Type: RedHat,
				Value: Cvss{
					Type:  CVSS2,
					Score: 8.0,
				},
			},
		},
		{
			in: VulnInfo{
				CveContents: CveContents{
					RedHat: {
						Type:       RedHat,
						Cvss3Score: 8.0,
					},
				},
			},
			out: CveContentCvss{
				Type: RedHat,
				Value: Cvss{
					Type:  CVSS3,
					Score: 8.0,
				},
			},
		},
		//2
		{
			in: VulnInfo{
				CveContents: CveContents{
					Ubuntu: {
						Type:     Ubuntu,
						Severity: "HIGH",
					},
				},
			},
			out: CveContentCvss{
				Type: Ubuntu,
				Value: Cvss{
					Type:                 CVSS2,
					Score:                8.9,
					CalculatedBySeverity: true,
					Severity:             "HIGH",
				},
			},
		},
		//3
		{
			in: VulnInfo{
				CveContents: CveContents{
					Ubuntu: {
						Type:     Ubuntu,
						Severity: "MEDIUM",
					},
					NVD: {
						Type:       NVD,
						Cvss2Score: 7.0,
					},
				},
			},
			out: CveContentCvss{
				Type: NVD,
				Value: Cvss{
					Type:     CVSS2,
					Score:    7.0,
					Severity: "HIGH",
				},
			},
		},
		//4
		{
			in: VulnInfo{
				DistroAdvisories: []DistroAdvisory{
					{
						Severity: "HIGH",
					},
				},
			},
			out: CveContentCvss{
				Type: "Vendor",
				Value: Cvss{
					Type:                 CVSS2,
					Score:                8.9,
					CalculatedBySeverity: true,
					Vector:               "-",
					Severity:             "HIGH",
				},
			},
		},
		{
			in: VulnInfo{
				CveContents: CveContents{
					Ubuntu: {
						Type:     Ubuntu,
						Severity: "MEDIUM",
					},
					NVD: {
						Type:       NVD,
						Cvss2Score: 4.0,
					},
				},
				DistroAdvisories: []DistroAdvisory{
					{
						Severity: "HIGH",
					},
				},
			},
			out: CveContentCvss{
				Type: NVD,
				Value: Cvss{
					Type:     CVSS2,
					Score:    4,
					Severity: "MEDIUM",
				},
			},
		},
		// Empty
		{
			in: VulnInfo{},
			out: CveContentCvss{
				Type: Unknown,
				Value: Cvss{
					Type:  CVSS2,
					Score: 0,
				},
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.MaxCvssScore()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\n[%d] expected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestFormatMaxCvssScore(t *testing.T) {
	var tests = []struct {
		in  VulnInfo
		out string
	}{
		{
			in: VulnInfo{
				CveContents: CveContents{
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
			},
			out: "8.3 HIGH (jvn)",
		},
		{
			in: VulnInfo{
				CveContents: CveContents{
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

func TestSortPackageStatues(t *testing.T) {
	var tests = []struct {
		in  PackageStatuses
		out PackageStatuses
	}{
		{
			in: PackageStatuses{
				{Name: "b"},
				{Name: "a"},
			},
			out: PackageStatuses{
				{Name: "a"},
				{Name: "b"},
			},
		},
	}
	for _, tt := range tests {
		tt.in.Sort()
		if !reflect.DeepEqual(tt.in, tt.out) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, tt.in)
		}
	}
}
