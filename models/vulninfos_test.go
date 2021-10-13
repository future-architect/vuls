package models

import (
	"reflect"
	"testing"
	"time"
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
						Jvn: []CveContent{{
							Type:  Jvn,
							Title: "Title1",
						}},
						RedHat: []CveContent{{
							Type:    RedHat,
							Summary: "Summary RedHat",
						}},
						Nvd: []CveContent{{
							Type:    Nvd,
							Summary: "Summary NVD",
							// Severity is NOT included in NVD
						}},
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  Jvn,
					Value: "Title1",
				},
				{
					Type:  Nvd,
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
						Jvn: []CveContent{{
							Type:  Jvn,
							Title: "Title1",
						}},
						RedHat: []CveContent{{
							Type:    RedHat,
							Summary: "Summary RedHat",
						}},
						Nvd: []CveContent{{
							Type:    Nvd,
							Summary: "Summary NVD",
							// Severity is NOT included in NVD
						}},
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  Nvd,
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
	for i, tt := range tests {
		actual := tt.in.cont.Titles(tt.in.lang, "redhat")
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
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
						Jvn: []CveContent{{
							Type:    Jvn,
							Title:   "Title JVN",
							Summary: "Summary JVN",
						}},
						RedHat: []CveContent{{
							Type:    RedHat,
							Summary: "Summary RedHat",
						}},
						Nvd: []CveContent{{
							Type:    Nvd,
							Summary: "Summary NVD",
							// Severity is NOT included in NVD
						}},
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  Jvn,
					Value: "Title JVN\nSummary JVN",
				},
				{
					Type:  RedHat,
					Value: "Summary RedHat",
				},
				{
					Type:  Nvd,
					Value: "Summary NVD",
				},
			},
		},
		// lang: en
		{
			in: in{
				lang: "en",
				cont: VulnInfo{
					CveContents: CveContents{
						Jvn: []CveContent{{
							Type:    Jvn,
							Title:   "Title JVN",
							Summary: "Summary JVN",
						}},
						RedHat: []CveContent{{
							Type:    RedHat,
							Summary: "Summary RedHat",
						}},
						Nvd: []CveContent{{
							Type:    Nvd,
							Summary: "Summary NVD",
							// Severity is NOT included in NVD
						}},
					},
				},
			},
			out: []CveContentStr{
				{
					Type:  RedHat,
					Value: "Summary RedHat",
				},
				{
					Type:  Nvd,
					Value: "Summary NVD",
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
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss3Score: 6.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss3Score: 2.0,
						}},
					},
				},
				"CVE-2017-0004": {
					CveID: "CVE-2017-0004",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss3Score: 5.0,
						}},
					},
				},
				"CVE-2017-0005": {
					CveID: "CVE-2017-0005",
				},
				"CVE-2017-0006": {
					CveID: "CVE-2017-0005",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss3Score: 10.0,
						}},
					},
				},
			},
			out: map[string]int{
				"Critical": 1,
				"High":     1,
				"Medium":   1,
				"Low":      1,
				"Unknown":  1,
			},
		},
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 1.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 2.0,
						}},
					},
				},
				"CVE-2017-0004": {
					CveID: "CVE-2017-0004",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 5.0,
						}},
					},
				},
				"CVE-2017-0005": {
					CveID: "CVE-2017-0005",
				},
				"CVE-2017-0006": {
					CveID: "CVE-2017-0005",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 10.0,
						}},
					},
				},
			},
			out: map[string]int{
				"Critical": 1,
				"High":     1,
				"Medium":   1,
				"Low":      1,
				"Unknown":  1,
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.CountGroupBySeverity()
		for k := range tt.out {
			if tt.out[k] != actual[k] {
				t.Errorf("[%d]\nexpected %s: %d\n  actual %d\n",
					i, k, tt.out[k], actual[k])
			}
		}
	}
}

func TestToSortedSlice(t *testing.T) {
	var tests = []struct {
		in  VulnInfos
		out []VulnInfo
	}{
		//0
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 6.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 7.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 8.0,
						}},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 7.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 8.0,
						}},
					},
				},
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 6.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
			},
		},
		//[1] When max scores are the same, sort by CVE-ID
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 6.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Nvd: []CveContent{{
							Type:       Nvd,
							Cvss2Score: 6.0,
						}},
						RedHat: []CveContent{{
							Type:       RedHat,
							Cvss3Score: 7.0,
						}},
					},
				},
			},
		},
		//[2] When there are no cvss scores, sort by severity
		{
			in: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Ubuntu: []CveContent{{
							Type:          Ubuntu,
							Cvss3Severity: "High",
						}},
					},
				},
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Ubuntu: []CveContent{{
							Type:          Ubuntu,
							Cvss3Severity: "Low",
						}},
					},
				},
			},
			out: []VulnInfo{
				{
					CveID: "CVE-2017-0002",
					CveContents: CveContents{
						Ubuntu: []CveContent{{
							Type:          Ubuntu,
							Cvss3Severity: "High",
						}},
					},
				},
				{
					CveID: "CVE-2017-0001",
					CveContents: CveContents{
						Ubuntu: []CveContent{{
							Type:          Ubuntu,
							Cvss3Severity: "Low",
						}},
					},
				},
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.ToSortedSlice()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
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
					Jvn: []CveContent{{
						Type:          Jvn,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.2,
						Cvss2Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					}},
					RedHat: []CveContent{{
						Type:          RedHat,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.0,
						Cvss2Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					}},
					Nvd: []CveContent{{
						Type:          Nvd,
						Cvss2Score:    8.1,
						Cvss2Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Cvss2Severity: "HIGH",
					}},
					//v3
					RedHatAPI: []CveContent{{
						Type:          RedHatAPI,
						Cvss3Score:    8.1,
						Cvss3Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Cvss3Severity: "HIGH",
					}},
				},
			},
			out: []CveContentCvss{
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
					Type: Nvd,
					Value: Cvss{
						Type:     CVSS2,
						Score:    8.1,
						Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						Severity: "HIGH",
					},
				},
				{
					Type: Jvn,
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
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestMaxCvss2Scores(t *testing.T) {
	var tests = []struct {
		in  VulnInfo
		out CveContentCvss
	}{
		// 0
		{
			in: VulnInfo{
				CveContents: CveContents{
					Jvn: []CveContent{{
						Type:          Jvn,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.2,
						Cvss2Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					}},
					RedHat: []CveContent{{
						Type:          RedHat,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.0,
						Cvss2Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
					}},
					Nvd: []CveContent{{
						Type:        Nvd,
						Cvss2Score:  8.1,
						Cvss2Vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
						// Severity is NOT included in NVD
					}},
				},
			},
			out: CveContentCvss{
				Type: Jvn,
				Value: Cvss{
					Type:     CVSS2,
					Score:    8.2,
					Vector:   "AV:N/AC:L/Au:N/C:N/I:N/A:P",
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
					RedHat: []CveContent{{
						Type:          RedHat,
						Cvss3Severity: "HIGH",
						Cvss3Score:    8.0,
						Cvss3Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
					}},
					Nvd: []CveContent{{
						Type:          Nvd,
						Cvss2Score:    8.1,
						Cvss2Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
						Cvss2Severity: "HIGH",
					}},
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
		// [1] Severity in OVAL
		{
			in: VulnInfo{
				CveContents: CveContents{
					Ubuntu: []CveContent{{
						Type:          Ubuntu,
						Cvss3Severity: "HIGH",
					}},
				},
			},
			out: []CveContentCvss{
				{
					Type: Ubuntu,
					Value: Cvss{
						Type:                 CVSS3,
						Score:                8.9,
						CalculatedBySeverity: true,
						Severity:             "HIGH",
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
		actual := tt.in.Cvss3Scores()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
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
					RedHat: []CveContent{{
						Type:          RedHat,
						Cvss3Severity: "HIGH",
						Cvss3Score:    8.0,
						Cvss3Vector:   "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
					}},
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
					Nvd: []CveContent{{
						Type:       Nvd,
						Cvss3Score: 7.0,
					}},
					RedHat: []CveContent{{
						Type:       RedHat,
						Cvss2Score: 8.0,
					}},
				},
			},
			out: CveContentCvss{
				Type: Nvd,
				Value: Cvss{
					Type:  CVSS3,
					Score: 7.0,
				},
			},
		},
		{
			in: VulnInfo{
				CveContents: CveContents{
					RedHat: []CveContent{{
						Type:       RedHat,
						Cvss3Score: 8.0,
					}},
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
					Ubuntu: []CveContent{{
						Type:          Ubuntu,
						Cvss3Severity: "HIGH",
					}},
				},
			},
			out: CveContentCvss{
				Type: Ubuntu,
				Value: Cvss{
					Type:                 CVSS3,
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
					Ubuntu: []CveContent{{
						Type:          Ubuntu,
						Cvss3Severity: "MEDIUM",
					}},
					Nvd: []CveContent{{
						Type:          Nvd,
						Cvss2Score:    7.0,
						Cvss2Severity: "HIGH",
					}},
				},
			},
			out: CveContentCvss{
				Type: Ubuntu,
				Value: Cvss{
					Type:                 CVSS3,
					Score:                6.9,
					Severity:             "MEDIUM",
					CalculatedBySeverity: true,
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
					Type:                 CVSS3,
					Score:                8.9,
					CalculatedBySeverity: true,
					Severity:             "HIGH",
				},
			},
		},
		//5
		{
			in: VulnInfo{
				CveContents: CveContents{
					Ubuntu: []CveContent{{
						Type:          Ubuntu,
						Cvss3Severity: "MEDIUM",
					}},
					Nvd: []CveContent{{
						Type:          Nvd,
						Cvss2Score:    4.0,
						Cvss2Severity: "MEDIUM",
					}},
				},
				DistroAdvisories: []DistroAdvisory{
					{
						Severity: "HIGH",
					},
				},
			},
			out: CveContentCvss{
				Type: "Vendor",
				Value: Cvss{
					Type:                 CVSS3,
					Score:                8.9,
					Severity:             "HIGH",
					CalculatedBySeverity: true,
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
					Jvn: []CveContent{{
						Type:          Jvn,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.3,
					}},
					RedHat: []CveContent{{
						Type:          RedHat,
						Cvss3Severity: "HIGH",
						Cvss3Score:    8.0,
					}},
					Nvd: []CveContent{{
						Type:       Nvd,
						Cvss2Score: 8.1,
						// Severity is NOT included in NVD
					}},
				},
			},
			out: "8.0 HIGH (redhat)",
		},
		{
			in: VulnInfo{
				CveContents: CveContents{
					Jvn: []CveContent{{
						Type:          Jvn,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.3,
					}},
					RedHat: []CveContent{{
						Type:          RedHat,
						Cvss2Severity: "HIGH",
						Cvss2Score:    8.0,
						Cvss3Severity: "HIGH",
						Cvss3Score:    9.9,
					}},
					Nvd: []CveContent{{
						Type:       Nvd,
						Cvss2Score: 8.1,
					}},
				},
			},
			out: "9.9 HIGH (redhat)",
		},
	}
	for i, tt := range tests {
		actual := tt.in.FormatMaxCvssScore()
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestSortPackageStatues(t *testing.T) {
	var tests = []struct {
		in  PackageFixStatuses
		out PackageFixStatuses
	}{
		{
			in: PackageFixStatuses{
				{Name: "b"},
				{Name: "a"},
			},
			out: PackageFixStatuses{
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

func TestStorePackageStatuses(t *testing.T) {
	var tests = []struct {
		pkgstats PackageFixStatuses
		in       PackageFixStatus
		out      PackageFixStatuses
	}{
		{
			pkgstats: PackageFixStatuses{
				{Name: "a"},
				{Name: "b"},
			},
			in: PackageFixStatus{
				Name: "c",
			},
			out: PackageFixStatuses{
				{Name: "a"},
				{Name: "b"},
				{Name: "c"},
			},
		},
	}
	for _, tt := range tests {
		out := tt.pkgstats.Store(tt.in)
		if ok := reflect.DeepEqual(tt.out, out); !ok {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, out)
		}
	}
}

func TestAppendIfMissing(t *testing.T) {
	var tests = []struct {
		in  Confidences
		arg Confidence
		out Confidences
	}{
		{
			in: Confidences{
				NvdExactVersionMatch,
			},
			arg: NvdExactVersionMatch,
			out: Confidences{
				NvdExactVersionMatch,
			},
		},
		{
			in: Confidences{
				NvdExactVersionMatch,
			},
			arg: ChangelogExactMatch,
			out: Confidences{
				NvdExactVersionMatch,
				ChangelogExactMatch,
			},
		},
	}
	for _, tt := range tests {
		tt.in.AppendIfMissing(tt.arg)
		if !reflect.DeepEqual(tt.in, tt.out) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, tt.in)
		}
	}
}

func TestSortByConfident(t *testing.T) {
	var tests = []struct {
		in  Confidences
		out Confidences
	}{
		{
			in: Confidences{
				OvalMatch,
				NvdExactVersionMatch,
			},
			out: Confidences{
				OvalMatch,
				NvdExactVersionMatch,
			},
		},
		{
			in: Confidences{
				NvdExactVersionMatch,
				OvalMatch,
			},
			out: Confidences{
				OvalMatch,
				NvdExactVersionMatch,
			},
		},
	}
	for _, tt := range tests {
		act := tt.in.SortByConfident()
		if !reflect.DeepEqual(tt.out, act) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.out, act)
		}
	}
}

func TestDistroAdvisories_AppendIfMissing(t *testing.T) {
	type args struct {
		adv *DistroAdvisory
	}
	tests := []struct {
		name  string
		advs  DistroAdvisories
		args  args
		want  bool
		after DistroAdvisories
	}{
		{
			name: "duplicate no append",
			advs: DistroAdvisories{
				DistroAdvisory{
					AdvisoryID: "ALASs-2019-1214",
				}},
			args: args{
				adv: &DistroAdvisory{
					AdvisoryID: "ALASs-2019-1214",
				},
			},
			want: false,
			after: DistroAdvisories{
				DistroAdvisory{
					AdvisoryID: "ALASs-2019-1214",
				}},
		},
		{
			name: "append",
			advs: DistroAdvisories{
				DistroAdvisory{
					AdvisoryID: "ALASs-2019-1214",
				}},
			args: args{
				adv: &DistroAdvisory{
					AdvisoryID: "ALASs-2019-1215",
				},
			},
			want: true,
			after: DistroAdvisories{
				{
					AdvisoryID: "ALASs-2019-1214",
				},
				{
					AdvisoryID: "ALASs-2019-1215",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.advs.AppendIfMissing(tt.args.adv); got != tt.want {
				t.Errorf("DistroAdvisories.AppendIfMissing() = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(tt.advs, tt.after) {
				t.Errorf("\nexpected: %v\n  actual: %v\n", tt.after, tt.advs)
			}
		})
	}
}

func TestVulnInfo_AttackVector(t *testing.T) {
	type fields struct {
		CveContents CveContents
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "2.0:N",
			fields: fields{
				CveContents: NewCveContents(
					CveContent{
						Type:        "foo",
						Cvss2Vector: "AV:N/AC:L/Au:N/C:C/I:C/A:C",
					},
				),
			},
			want: "AV:N",
		},
		{
			name: "2.0:A",
			fields: fields{
				CveContents: NewCveContents(
					CveContent{
						Type:        "foo",
						Cvss2Vector: "AV:A/AC:L/Au:N/C:C/I:C/A:C",
					},
				),
			},
			want: "AV:A",
		},
		{
			name: "2.0:L",
			fields: fields{
				CveContents: NewCveContents(
					CveContent{
						Type:        "foo",
						Cvss2Vector: "AV:L/AC:L/Au:N/C:C/I:C/A:C",
					},
				),
			},
			want: "AV:L",
		},

		{
			name: "3.0:N",
			fields: fields{
				CveContents: NewCveContents(
					CveContent{
						Type:        "foo",
						Cvss3Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				),
			},
			want: "AV:N",
		},
		{
			name: "3.1:N",
			fields: fields{
				CveContents: NewCveContents(
					CveContent{
						Type:        "foo",
						Cvss3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
					},
				),
			},
			want: "AV:N",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := VulnInfo{
				CveContents: tt.fields.CveContents,
			}
			if got := v.AttackVector(); got != tt.want {
				t.Errorf("VulnInfo.AttackVector() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVulnInfos_FilterByCvssOver(t *testing.T) {
	type args struct {
		over float64
	}
	tests := []struct {
		name  string
		v     VulnInfos
		args  args
		want  VulnInfos
		nwant int
	}{
		{
			name: "over 7.0",
			args: args{over: 7.0},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: NewCveContents(
						CveContent{
							Type:         Nvd,
							CveID:        "CVE-2017-0001",
							Cvss2Score:   7.1,
							LastModified: time.Time{},
						},
					),
				},
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: NewCveContents(
						CveContent{
							Type:         Nvd,
							CveID:        "CVE-2017-0002",
							Cvss2Score:   6.9,
							LastModified: time.Time{},
						},
					),
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: NewCveContents(
						CveContent{
							Type:         Nvd,
							CveID:        "CVE-2017-0003",
							Cvss2Score:   6.9,
							LastModified: time.Time{},
						},
						CveContent{
							Type:         Jvn,
							CveID:        "CVE-2017-0003",
							Cvss2Score:   7.2,
							LastModified: time.Time{},
						},
					),
				},
			},
			nwant: 1,
			want: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: NewCveContents(
						CveContent{
							Type:         Nvd,
							CveID:        "CVE-2017-0001",
							Cvss2Score:   7.1,
							LastModified: time.Time{},
						},
					),
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: NewCveContents(
						CveContent{
							Type:         Nvd,
							CveID:        "CVE-2017-0003",
							Cvss2Score:   6.9,
							LastModified: time.Time{},
						},
						CveContent{
							Type:         Jvn,
							CveID:        "CVE-2017-0003",
							Cvss2Score:   7.2,
							LastModified: time.Time{},
						},
					),
				},
			},
		},
		{
			name: "over high",
			args: args{over: 7.0},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: NewCveContents(
						CveContent{
							Type:          Ubuntu,
							CveID:         "CVE-2017-0001",
							Cvss3Severity: "HIGH",
							LastModified:  time.Time{},
						},
					),
				},
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: NewCveContents(
						CveContent{
							Type:          Debian,
							CveID:         "CVE-2017-0002",
							Cvss3Severity: "CRITICAL",
							LastModified:  time.Time{},
						},
					),
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: NewCveContents(
						CveContent{
							Type:          GitHub,
							CveID:         "CVE-2017-0003",
							Cvss3Severity: "IMPORTANT",
							LastModified:  time.Time{},
						},
					),
				},
			},
			want: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					CveContents: NewCveContents(
						CveContent{
							Type:          Ubuntu,
							CveID:         "CVE-2017-0001",
							Cvss3Severity: "HIGH",
							LastModified:  time.Time{},
						},
					),
				},
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					CveContents: NewCveContents(
						CveContent{
							Type:          Debian,
							CveID:         "CVE-2017-0002",
							Cvss3Severity: "CRITICAL",
							LastModified:  time.Time{},
						},
					),
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					CveContents: NewCveContents(
						CveContent{
							Type:          GitHub,
							CveID:         "CVE-2017-0003",
							Cvss3Severity: "IMPORTANT",
							LastModified:  time.Time{},
						},
					),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ngot := tt.v.FilterByCvssOver(tt.args.over)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VulnInfos.FindByCvssOver() = %v, want %v", got, tt.want)
			}
			if ngot != tt.nwant {
				t.Errorf("VulnInfos.FindByCvssOver() = %d, want %d", ngot, tt.nwant)
			}
		})
	}
}

func TestVulnInfos_FilterIgnoreCves(t *testing.T) {
	type args struct {
		ignoreCveIDs []string
	}
	tests := []struct {
		name  string
		v     VulnInfos
		args  args
		want  VulnInfos
		nwant int
	}{
		{
			name: "filter ignored",
			args: args{ignoreCveIDs: []string{"CVE-2017-0002"}},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
				},
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
				},
			},
			nwant: 1,
			want: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ngot := tt.v.FilterIgnoreCves(tt.args.ignoreCveIDs)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VulnInfos.FindIgnoreCves() = %v, want %v", got, tt.want)
			}
			if ngot != tt.nwant {
				t.Errorf("VulnInfos.FindByCvssOver() = %d, want %d", ngot, tt.nwant)
			}
		})
	}
}

func TestVulnInfos_FilterUnfixed(t *testing.T) {
	type args struct {
		ignoreUnfixed bool
	}
	tests := []struct {
		name  string
		v     VulnInfos
		args  args
		want  VulnInfos
		nwant int
	}{
		{
			name: "filter ok",
			args: args{ignoreUnfixed: true},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					AffectedPackages: PackageFixStatuses{
						{
							Name:        "a",
							NotFixedYet: true,
						},
					},
				},
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					AffectedPackages: PackageFixStatuses{
						{
							Name:        "b",
							NotFixedYet: false,
						},
					},
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					AffectedPackages: PackageFixStatuses{
						{
							Name:        "c",
							NotFixedYet: true,
						},
						{
							Name:        "d",
							NotFixedYet: false,
						},
					},
				},
			},
			nwant: 1,
			want: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
					AffectedPackages: PackageFixStatuses{
						{
							Name:        "b",
							NotFixedYet: false,
						},
					},
				},
				"CVE-2017-0003": {
					CveID: "CVE-2017-0003",
					AffectedPackages: PackageFixStatuses{
						{
							Name:        "c",
							NotFixedYet: true,
						},
						{
							Name:        "d",
							NotFixedYet: false,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ngot := tt.v.FilterUnfixed(tt.args.ignoreUnfixed)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VulnInfos.FilterUnfixed() = %v, want %v", got, tt.want)
			}
			if ngot != tt.nwant {
				t.Errorf("VulnInfos.FindByCvssOver() = %d, want %d", ngot, tt.nwant)
			}
		})
	}
}

func TestVulnInfos_FilterIgnorePkgs(t *testing.T) {
	type args struct {
		ignorePkgsRegexps []string
	}
	tests := []struct {
		name  string
		v     VulnInfos
		args  args
		want  VulnInfos
		nwant int
	}{
		{
			name: "filter pkgs 1",
			args: args{ignorePkgsRegexps: []string{"^kernel"}},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					AffectedPackages: PackageFixStatuses{
						{Name: "kernel"},
					},
				},
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
				},
			},
			nwant: 1,
			want: VulnInfos{
				"CVE-2017-0002": {
					CveID: "CVE-2017-0002",
				},
			},
		},
		{
			name: "filter pkgs 2",
			args: args{ignorePkgsRegexps: []string{"^kernel"}},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					AffectedPackages: PackageFixStatuses{
						{Name: "kernel"},
						{Name: "vim"},
					},
				},
			},
			nwant: 0,
			want: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					AffectedPackages: PackageFixStatuses{
						{Name: "kernel"},
						{Name: "vim"},
					},
				},
			},
		},
		{
			name: "filter pkgs 3",
			args: args{ignorePkgsRegexps: []string{"^kernel", "^vim", "^bind"}},
			v: VulnInfos{
				"CVE-2017-0001": {
					CveID: "CVE-2017-0001",
					AffectedPackages: PackageFixStatuses{
						{Name: "kernel"},
						{Name: "vim"},
					},
				},
			},
			nwant: 1,
			want:  VulnInfos{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ngot := tt.v.FilterIgnorePkgs(tt.args.ignorePkgsRegexps)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VulnInfos.FilterIgnorePkgs() = %v, want %v", got, tt.want)
			}
			if ngot != tt.nwant {
				t.Errorf("VulnInfos.FilterIgnorePkgs() = %d, want %d", ngot, tt.nwant)
			}
		})
	}
}

func TestVulnInfos_FilterByConfidenceOver(t *testing.T) {
	type args struct {
		over int
	}
	tests := []struct {
		name  string
		v     VulnInfos
		args  args
		want  VulnInfos
		nwant int
	}{
		{
			name: "over 0",
			v: map[string]VulnInfo{
				"CVE-2021-1111": {
					CveID:       "CVE-2021-1111",
					Confidences: Confidences{JvnVendorProductMatch},
				},
			},
			args: args{
				over: 0,
			},
			want: map[string]VulnInfo{
				"CVE-2021-1111": {
					CveID:       "CVE-2021-1111",
					Confidences: Confidences{JvnVendorProductMatch},
				},
			},
		},
		{
			name: "over 20",
			v: map[string]VulnInfo{
				"CVE-2021-1111": {
					CveID:       "CVE-2021-1111",
					Confidences: Confidences{JvnVendorProductMatch},
				},
			},
			args: args{
				over: 20,
			},
			nwant: 1,
			want:  map[string]VulnInfo{},
		},
		{
			name: "over 100",
			v: map[string]VulnInfo{
				"CVE-2021-1111": {
					CveID: "CVE-2021-1111",
					Confidences: Confidences{
						NvdExactVersionMatch,
						JvnVendorProductMatch,
					},
				},
			},
			args: args{
				over: 20,
			},
			want: map[string]VulnInfo{
				"CVE-2021-1111": {
					CveID: "CVE-2021-1111",
					Confidences: Confidences{
						NvdExactVersionMatch,
						JvnVendorProductMatch,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ngot := tt.v.FilterByConfidenceOver(tt.args.over)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("VulnInfos.FilterByConfidenceOver() = %v, want %v", got, tt.want)
			}
			if ngot != tt.nwant {
				t.Errorf("VulnInfos.FilterByConfidenceOver() = %d, want %d", ngot, tt.nwant)
			}
		})
	}
}
