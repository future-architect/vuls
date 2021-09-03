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
