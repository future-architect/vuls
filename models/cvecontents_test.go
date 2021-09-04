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
			RedHat: []CveContent{{Type: RedHat}},
			Ubuntu: []CveContent{{Type: Ubuntu}},
			Debian: []CveContent{{Type: Debian}},
		},
		out: CveContents{
			RedHat: []CveContent{{Type: RedHat}},
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
		lang        string
		cveID       string
		cont        CveContents
		confidences Confidences
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
					Jvn: []CveContent{{
						Type:       Jvn,
						SourceLink: "https://jvn.jp/vu/JVNVU93610402/",
					}},
					RedHat: []CveContent{{
						Type:       RedHat,
						SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
					}},
					Nvd: []CveContent{{
						Type: Nvd,
						References: []Reference{
							{
								Link:   "https://lists.apache.org/thread.html/765be3606d865de513f6df9288842c3cf58b09a987c617a535f2b99d@%3Cusers.tapestry.apache.org%3E",
								Source: "",
								RefID:  "",
								Tags:   []string{"Vendor Advisory"},
							},
							{
								Link:   "http://yahoo.com",
								Source: "",
								RefID:  "",
								Tags:   []string{"Vendor"},
							},
						},
						SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
					}},
				},
			},
			out: []CveContentStr{
				{
					Type:  Nvd,
					Value: "https://lists.apache.org/thread.html/765be3606d865de513f6df9288842c3cf58b09a987c617a535f2b99d@%3Cusers.tapestry.apache.org%3E",
				},
				{
					Type:  Nvd,
					Value: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
				},
				{
					Type:  RedHat,
					Value: "https://access.redhat.com/security/cve/CVE-2017-6074",
				},
				{
					Type:  Jvn,
					Value: "https://jvn.jp/vu/JVNVU93610402/",
				},
			},
		},
		// lang: en
		{
			in: in{
				lang:  "en",
				cveID: "CVE-2017-6074",
				cont: CveContents{
					Jvn: []CveContent{{
						Type:       Jvn,
						SourceLink: "https://jvn.jp/vu/JVNVU93610402/",
					}},
					RedHat: []CveContent{{
						Type:       RedHat,
						SourceLink: "https://access.redhat.com/security/cve/CVE-2017-6074",
					}},
				},
			},
			out: []CveContentStr{
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
					Type:  Nvd,
					Value: "https://nvd.nist.gov/vuln/detail/CVE-2017-6074",
				},
			},
		},
		// Confidence: JvnVendorProductMatch
		{
			in: in{
				lang:  "en",
				cveID: "CVE-2017-6074",
				cont: CveContents{
					Jvn: []CveContent{{
						Type:       Jvn,
						SourceLink: "https://jvn.jp/vu/JVNVU93610402/",
					}},
				},
				confidences: Confidences{
					Confidence{DetectionMethod: JvnVendorProductMatchStr},
				},
			},
			out: []CveContentStr{
				{
					Type:  Jvn,
					Value: "https://jvn.jp/vu/JVNVU93610402/",
				},
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.cont.PrimarySrcURLs(tt.in.lang, "redhat", tt.in.cveID, tt.in.confidences)
		if !reflect.DeepEqual(tt.out, actual) {
			t.Errorf("\n[%d] expected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestCveContents_Sort(t *testing.T) {
	tests := []struct {
		name string
		v    CveContents
		want CveContents
	}{
		{
			name: "sorted",
			v: map[CveContentType][]CveContent{
				"jvn": {
					{Cvss3Score: 3},
					{Cvss3Score: 10},
				},
			},
			want: map[CveContentType][]CveContent{
				"jvn": {
					{Cvss3Score: 10},
					{Cvss3Score: 3},
				},
			},
		},
		{
			name: "sort JVN by cvss3, cvss2, sourceLink",
			v: map[CveContentType][]CveContent{
				"jvn": {
					{
						Cvss3Score: 3,
						Cvss2Score: 3,
						SourceLink: "https://jvndb.jvn.jp/ja/contents/2023/JVNDB-2023-001210.html",
					},
					{
						Cvss3Score: 3,
						Cvss2Score: 3,
						SourceLink: "https://jvndb.jvn.jp/ja/contents/2021/JVNDB-2021-001210.html",
					},
				},
			},
			want: map[CveContentType][]CveContent{
				"jvn": {
					{
						Cvss3Score: 3,
						Cvss2Score: 3,
						SourceLink: "https://jvndb.jvn.jp/ja/contents/2021/JVNDB-2021-001210.html",
					},
					{
						Cvss3Score: 3,
						Cvss2Score: 3,
						SourceLink: "https://jvndb.jvn.jp/ja/contents/2023/JVNDB-2023-001210.html",
					},
				},
			},
		},
		{
			name: "sort JVN by cvss3, cvss2",
			v: map[CveContentType][]CveContent{
				"jvn": {
					{
						Cvss3Score: 3,
						Cvss2Score: 1,
					},
					{
						Cvss3Score: 3,
						Cvss2Score: 10,
					},
				},
			},
			want: map[CveContentType][]CveContent{
				"jvn": {
					{
						Cvss3Score: 3,
						Cvss2Score: 10,
					},
					{
						Cvss3Score: 3,
						Cvss2Score: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.v.Sort()
			if !reflect.DeepEqual(tt.v, tt.want) {
				t.Errorf("\n[%s] expected: %v\n  actual: %v\n", tt.name, tt.want, tt.v)
			}
		})
	}
}
