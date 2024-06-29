package models

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/constant"
)

func TestCveContents_Except(t *testing.T) {
	type args struct {
		exceptCtypes []CveContentType
	}
	tests := []struct {
		name       string
		v          CveContents
		args       args
		wantValues CveContents
	}{
		{
			name: "happy",
			v: CveContents{
				RedHat: []CveContent{{Type: RedHat}},
				Ubuntu: []CveContent{{Type: Ubuntu}},
				Debian: []CveContent{{Type: Debian}},
			},
			args: args{
				exceptCtypes: []CveContentType{Ubuntu, Debian},
			},
			wantValues: CveContents{
				RedHat: []CveContent{{Type: RedHat}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotValues := tt.v.Except(tt.args.exceptCtypes...); !reflect.DeepEqual(gotValues, tt.wantValues) {
				t.Errorf("CveContents.Except() = %v, want %v", gotValues, tt.wantValues)
			}
		})
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
					Type:  Jvn,
					Value: "https://jvn.jp/vu/JVNVU93610402/",
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

func TestCveContents_PatchURLs(t *testing.T) {
	tests := []struct {
		name     string
		v        CveContents
		wantUrls []string
	}{
		{
			name: "happy",
			v: CveContents{
				Nvd: []CveContent{
					{
						References: []Reference{
							{
								Link:   "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625",
								Source: "cve@mitre.org",
								Tags:   []string{"Patch", "Vendor Advisory"},
							},
							{
								Link:   "https://lists.debian.org/debian-lts-announce/2020/01/msg00013.html",
								Source: "cve@mitre.org",
								Tags:   []string{"Mailing List", "Third Party Advisory"},
							},
						},
					},
					{
						References: []Reference{
							{
								Link: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625",
								Tags: []string{"Patch", "Vendor Advisory"},
							},
						},
					},
				},
			},
			wantUrls: []string{"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotUrls := tt.v.PatchURLs(); !reflect.DeepEqual(gotUrls, tt.wantUrls) {
				t.Errorf("CveContents.PatchURLs() = %v, want %v", gotUrls, tt.wantUrls)
			}
		})
	}
}

func TestCveContents_Cpes(t *testing.T) {
	type args struct {
		myFamily string
	}
	tests := []struct {
		name       string
		v          CveContents
		args       args
		wantValues []CveContentCpes
	}{
		{
			name: "happy",
			v: CveContents{
				Nvd: []CveContent{{
					Cpes: []Cpe{{
						URI:             "cpe:/a:microsoft:internet_explorer:8.0.6001:beta",
						FormattedString: "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*",
					}},
				}},
			},
			args: args{myFamily: "redhat"},
			wantValues: []CveContentCpes{{
				Type: Nvd,
				Value: []Cpe{{
					URI:             "cpe:/a:microsoft:internet_explorer:8.0.6001:beta",
					FormattedString: "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*",
				}},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotValues := tt.v.Cpes(tt.args.myFamily); !reflect.DeepEqual(gotValues, tt.wantValues) {
				t.Errorf("CveContents.Cpes() = %v, want %v", gotValues, tt.wantValues)
			}
		})
	}
}
func TestCveContents_References(t *testing.T) {
	type args struct {
		myFamily string
	}
	tests := []struct {
		name       string
		v          CveContents
		args       args
		wantValues []CveContentRefs
	}{
		{
			name: "happy",
			v: CveContents{
				Mitre: []CveContent{{CveID: "CVE-2024-0001"}},
				Nvd: []CveContent{
					{
						References: []Reference{
							{
								Link:   "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625",
								Source: "cve@mitre.org",
								Tags:   []string{"Patch", "Vendor Advisory"},
							},
							{
								Link:   "https://lists.debian.org/debian-lts-announce/2020/01/msg00013.html",
								Source: "cve@mitre.org",
								Tags:   []string{"Mailing List", "Third Party Advisory"},
							},
						},
					},
					{
						References: []Reference{
							{
								Link: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625",
								Tags: []string{"Patch", "Vendor Advisory"},
							},
						},
					},
				},
			},
			wantValues: []CveContentRefs{
				{
					Type: Nvd,
					Value: []Reference{
						{
							Link:   "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625",
							Source: "cve@mitre.org",
							Tags:   []string{"Patch", "Vendor Advisory"},
						},
						{
							Link:   "https://lists.debian.org/debian-lts-announce/2020/01/msg00013.html",
							Source: "cve@mitre.org",
							Tags:   []string{"Mailing List", "Third Party Advisory"},
						},
					},
				},
				{
					Type: Nvd,
					Value: []Reference{
						{
							Link: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=c52873e5a1ef72f845526d9f6a50704433f9c625",
							Tags: []string{"Patch", "Vendor Advisory"},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotValues := tt.v.References(tt.args.myFamily); !reflect.DeepEqual(gotValues, tt.wantValues) {
				t.Errorf("CveContents.References() = %v, want %v", gotValues, tt.wantValues)
			}
		})
	}
}

func TestCveContents_CweIDs(t *testing.T) {
	type args struct {
		myFamily string
	}
	tests := []struct {
		name       string
		v          CveContents
		args       args
		wantValues []CveContentStr
	}{
		{
			name: "happy",
			v: CveContents{
				Mitre: []CveContent{{CweIDs: []string{"CWE-001"}}},
				Nvd: []CveContent{
					{CweIDs: []string{"CWE-001"}},
					{CweIDs: []string{"CWE-001"}},
				},
			},
			args: args{myFamily: "redhat"},
			wantValues: []CveContentStr{
				{
					Type:  Mitre,
					Value: "CWE-001",
				},
				{
					Type:  Nvd,
					Value: "CWE-001",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotValues := tt.v.CweIDs(tt.args.myFamily); !reflect.DeepEqual(gotValues, tt.wantValues) {
				t.Errorf("CveContents.CweIDs() = %v, want %v", gotValues, tt.wantValues)
			}
		})
	}
}

func TestCveContents_UniqCweIDs(t *testing.T) {
	type args struct {
		myFamily string
	}
	tests := []struct {
		name string
		v    CveContents
		args args
		want []CveContentStr
	}{
		{
			name: "happy",
			v: CveContents{
				Mitre: []CveContent{{CweIDs: []string{"CWE-001"}}},
				Nvd: []CveContent{
					{CweIDs: []string{"CWE-001"}},
					{CweIDs: []string{"CWE-001"}},
				},
			},
			args: args{myFamily: "redhat"},
			want: []CveContentStr{
				{
					Type:  Nvd,
					Value: "CWE-001",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.UniqCweIDs(tt.args.myFamily); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CveContents.UniqCweIDs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCveContents_SSVC(t *testing.T) {
	tests := []struct {
		name string
		v    CveContents
		want []CveContentSSVC
	}{
		{
			name: "happy",
			v: CveContents{
				Mitre: []CveContent{
					{
						Type:     Mitre,
						CveID:    "CVE-2024-5732",
						Title:    "Clash Proxy Port improper authentication",
						Optional: map[string]string{"source": "CNA"},
					},
					{
						Type:  Mitre,
						CveID: "CVE-2024-5732",
						Title: "CISA ADP Vulnrichment",
						SSVC: &SSVC{
							Exploitation:    "none",
							Automatable:     "no",
							TechnicalImpact: "partial",
						},
						Optional: map[string]string{"source": "ADP:CISA-ADP"},
					},
				},
			},
			want: []CveContentSSVC{
				{
					Type: "mitre(ADP:CISA-ADP)",
					Value: SSVC{
						Exploitation:    "none",
						Automatable:     "no",
						TechnicalImpact: "partial",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.v.SSVC(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CveContents.SSVC() = %v, want %v", got, tt.want)
			}
		})
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
		{
			name: "sort CVSS v4.0",
			v: CveContents{
				Mitre: []CveContent{
					{Cvss40Score: 0},
					{Cvss40Score: 6.9},
				},
			},
			want: CveContents{
				Mitre: []CveContent{
					{Cvss40Score: 6.9},
					{Cvss40Score: 0},
				},
			},
		},
		{
			name: "sort CVSS v4.0 and CVSS v3",
			v: CveContents{
				Mitre: []CveContent{
					{
						Cvss40Score: 0,
						Cvss3Score:  7.3,
					},
					{
						Cvss40Score: 0,
						Cvss3Score:  9.8,
					},
				},
			},
			want: CveContents{
				Mitre: []CveContent{
					{
						Cvss40Score: 0,
						Cvss3Score:  9.8,
					},
					{
						Cvss40Score: 0,
						Cvss3Score:  7.3,
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

func TestCveContent_Empty(t *testing.T) {
	type fields struct {
		Type    CveContentType
		CveID   string
		Title   string
		Summary string
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "empty",
			fields: fields{
				Summary: "",
			},
			want: true,
		},
		{
			name: "not empty",
			fields: fields{
				Summary: "summary",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (CveContent{
				Type:    tt.fields.Type,
				CveID:   tt.fields.CveID,
				Title:   tt.fields.Title,
				Summary: tt.fields.Summary,
			}).Empty(); got != tt.want {
				t.Errorf("CveContent.Empty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewCveContentType(t *testing.T) {
	tests := []struct {
		name string
		want CveContentType
	}{
		{
			name: "redhat",
			want: RedHat,
		},
		{
			name: "centos",
			want: RedHat,
		},
		{
			name: "unknown",
			want: Unknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewCveContentType(tt.name); got != tt.want {
				t.Errorf("NewCveContentType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetCveContentTypes(t *testing.T) {
	tests := []struct {
		family string
		want   []CveContentType
	}{
		{
			family: constant.RedHat,
			want:   []CveContentType{RedHat, RedHatAPI},
		},
		{
			family: constant.Debian,
			want:   []CveContentType{Debian, DebianSecurityTracker},
		},
		{
			family: constant.Ubuntu,
			want:   []CveContentType{Ubuntu, UbuntuAPI},
		},
		{
			family: constant.FreeBSD,
			want:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.family, func(t *testing.T) {
			if got := GetCveContentTypes(tt.family); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetCveContentTypes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCveContentTypes_Except(t *testing.T) {
	type args struct {
		excepts []CveContentType
	}
	tests := []struct {
		name         string
		c            CveContentTypes
		args         args
		wantExcepted CveContentTypes
	}{
		{
			name: "happy",
			c:    CveContentTypes{Ubuntu, UbuntuAPI},
			args: args{
				excepts: []CveContentType{Ubuntu},
			},
			wantExcepted: CveContentTypes{UbuntuAPI},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotExcepted := tt.c.Except(tt.args.excepts...); !reflect.DeepEqual(gotExcepted, tt.wantExcepted) {
				t.Errorf("CveContentTypes.Except() = %v, want %v", gotExcepted, tt.wantExcepted)
			}
		})
	}
}
