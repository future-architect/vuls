package models

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/cwe"
)

func TestIsDisplayUpdatableNum(t *testing.T) {
	var tests = []struct {
		mode     []byte
		family   string
		expected bool
	}{
		{
			mode:     []byte{config.Offline},
			expected: false,
		},
		{
			mode:     []byte{config.FastRoot},
			expected: true,
		},
		{
			mode:     []byte{config.Deep},
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.RedHat,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Oracle,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Debian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Ubuntu,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Raspbian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.CentOS,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Alma,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Rocky,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Amazon,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.FreeBSD,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.OpenSUSE,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Alpine,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Fedora,
			expected: true,
		},
	}

	for i, tt := range tests {
		mode := config.ScanMode{}
		for _, m := range tt.mode {
			mode.Set(m)
		}
		r := ScanResult{
			ServerName: "name",
			Family:     tt.family,
		}
		act := r.isDisplayUpdatableNum(mode)
		if tt.expected != act {
			t.Errorf("[%d] expected %#v, actual %#v", i, tt.expected, act)
		}
	}
}

func TestScanResult_Sort(t *testing.T) {
	type fields struct {
		Packages    Packages
		ScannedCves VulnInfos
	}
	tests := []struct {
		name     string
		fields   fields
		expected fields
	}{
		{
			name: "already asc",
			fields: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "1", Name: "procB"},
							{PID: "2", Name: "procA"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "1"},
							{PID: "2"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgA"},
							PackageFixStatus{Name: "pkgB"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-1"},
							{AdvisoryID: "adv-2"},
						},
						Exploits: []Exploit{
							{URL: "a"},
							{URL: "b"},
						},
						Metasploits: []Metasploit{
							{Name: "a"},
							{Name: "b"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							JPCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
						},
					},
				},
			},
			expected: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "1", Name: "procB"},
							{PID: "2", Name: "procA"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "1"},
							{PID: "2"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgA"},
							PackageFixStatus{Name: "pkgB"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-1"},
							{AdvisoryID: "adv-2"},
						},
						Exploits: []Exploit{
							{URL: "a"},
							{URL: "b"},
						},
						Metasploits: []Metasploit{
							{Name: "a"},
							{Name: "b"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							JPCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
						},
					},
				},
			},
		},
		{
			name: "sort",
			fields: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "2", Name: "procA"},
							{PID: "1", Name: "procB"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "91"},
							{PID: "90"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgB"},
							PackageFixStatus{Name: "pkgA"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-2"},
							{AdvisoryID: "adv-1"},
						},
						Exploits: []Exploit{
							{URL: "b"},
							{URL: "a"},
						},
						Metasploits: []Metasploit{
							{Name: "b"},
							{Name: "a"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "b"},
									Reference{Link: "a"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "b"},
									Reference{Link: "a"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "b"},
								{Title: "a"},
							},
							JPCERT: []Alert{
								{Title: "b"},
								{Title: "a"},
							},
						},
					},
				},
			},
			expected: fields{
				Packages: map[string]Package{
					"pkgA": {
						Name: "pkgA",
						AffectedProcs: []AffectedProcess{
							{PID: "1", Name: "procB"},
							{PID: "2", Name: "procA"},
						},
						NeedRestartProcs: []NeedRestartProcess{
							{PID: "90"},
							{PID: "91"},
						},
					},
				},
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						AffectedPackages: PackageFixStatuses{
							PackageFixStatus{Name: "pkgA"},
							PackageFixStatus{Name: "pkgB"},
						},
						DistroAdvisories: []DistroAdvisory{
							{AdvisoryID: "adv-1"},
							{AdvisoryID: "adv-2"},
						},
						Exploits: []Exploit{
							{URL: "a"},
							{URL: "b"},
						},
						Metasploits: []Metasploit{
							{Name: "a"},
							{Name: "b"},
						},
						CveContents: CveContents{
							"nvd": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
							"jvn": []CveContent{{
								References: References{
									Reference{Link: "a"},
									Reference{Link: "b"},
								}},
							},
						},
						AlertDict: AlertDict{
							USCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
							JPCERT: []Alert{
								{Title: "a"},
								{Title: "b"},
							},
						},
					},
				},
			},
		},
		{
			name: "sort JVN by cvss v3",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{Cvss3Score: 3},
								{Cvss3Score: 10},
							},
						},
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
								{Cvss3Score: 10},
								{Cvss3Score: 3},
							},
						},
					},
				},
			},
		},
		{
			name: "sort JVN by cvss3, cvss2, sourceLink",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
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
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
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
				},
			},
		},
		{
			name: "sort JVN by cvss3, cvss2",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
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
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-2014-3591": VulnInfo{
						CveContents: CveContents{
							"jvn": []CveContent{
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
				},
			},
		},
		{
			name: "sort kev 1",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-0000-0000": VulnInfo{
						KEVs: []KEV{
							{Type: VulnCheckKEVType},
							{Type: ENISAKEVType},
							{Type: CISAKEVType},
						},
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-0000-0000": VulnInfo{
						KEVs: []KEV{
							{Type: CISAKEVType},
							{Type: ENISAKEVType},
							{Type: VulnCheckKEVType},
						},
					},
				},
			},
		},
		{
			name: "sort kev 2",
			fields: fields{
				ScannedCves: VulnInfos{
					"CVE-0000-0000": VulnInfo{
						KEVs: []KEV{
							{
								Type:              CISAKEVType,
								VulnerabilityName: "name 2",
							},
							{
								Type:              CISAKEVType,
								VulnerabilityName: "name 1",
							},
						},
					},
				},
			},
			expected: fields{
				ScannedCves: VulnInfos{
					"CVE-0000-0000": VulnInfo{
						KEVs: []KEV{
							{
								Type:              CISAKEVType,
								VulnerabilityName: "name 1",
							},
							{
								Type:              CISAKEVType,
								VulnerabilityName: "name 2",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ScanResult{
				Packages:    tt.fields.Packages,
				ScannedCves: tt.fields.ScannedCves,
			}
			r.SortForJSONOutput()
			if !reflect.DeepEqual(r.Packages, tt.expected.Packages) {
				t.Errorf("act %+v, want %+v", r.Packages, tt.expected.Packages)
			}

			if !reflect.DeepEqual(r.ScannedCves, tt.expected.ScannedCves) {
				t.Errorf("act %+v, want %+v", r.ScannedCves, tt.expected.ScannedCves)
			}
		})
	}
}

func TestCWEDict_Get(t *testing.T) {
	type args struct {
		cweID string
		lang  string
	}
	tests := []struct {
		name      string
		c         CWEDict
		args      args
		wantName  string
		wantUrl   string
		wantOwasp map[string]AttentionCWE
		wantCwe25 map[string]AttentionCWE
		wantSans  map[string]AttentionCWE
	}{
		{
			name: "en/populated returns En name + mitre URL",
			c: CWEDict{
				"306": {
					En:                 &cwe.CWE{CWEID: "306", Name: "Missing Authentication for Critical Function", Lang: "en"},
					Ja:                 &cwe.CWE{CWEID: "306", Name: "重要な機能に対する認証の欠如", Lang: "ja"},
					OwaspTopTens:       map[string]string{"2021": "7"},
					CweTopTwentyfives:  map[string]string{"2024": "11"},
					SansTopTwentyfives: map[string]string{"2011": "11"},
				},
			},
			args:     args{cweID: "CWE-306", lang: "en"},
			wantName: "Missing Authentication for Critical Function",
			wantUrl:  "https://cwe.mitre.org/data/definitions/CWE-306.html",
			wantOwasp: map[string]AttentionCWE{"2021": {
				Rank: "7",
				URL:  cwe.OwaspTopTenURLsEn["2021"]["7"],
			}},
			wantCwe25: map[string]AttentionCWE{"2024": {
				Rank: "11",
				URL:  cwe.CweTopTwentyfiveURLs["2024"],
			}},
			wantSans: map[string]AttentionCWE{"2011": {
				Rank: "11",
				URL:  cwe.SansTopTwentyfiveURLs["2011"],
			}},
		},
		{
			name: "ja/Ja-populated returns Ja name + JVN URL",
			c: CWEDict{
				"306": {
					En:                 &cwe.CWE{CWEID: "306", Name: "Missing Authentication for Critical Function", Lang: "en"},
					Ja:                 &cwe.CWE{CWEID: "306", Name: "重要な機能に対する認証の欠如", Lang: "ja"},
					OwaspTopTens:       map[string]string{"2021": "7"},
					CweTopTwentyfives:  map[string]string{"2024": "11"},
					SansTopTwentyfives: map[string]string{"2011": "11"},
				},
			},
			args:     args{cweID: "CWE-306", lang: "ja"},
			wantName: "重要な機能に対する認証の欠如",
			wantUrl:  "http://jvndb.jvn.jp/ja/cwe/CWE-306.html",
			wantOwasp: map[string]AttentionCWE{"2021": {
				Rank: "7",
				URL:  cwe.OwaspTopTenURLsJa["2021"]["7"],
			}},
			wantCwe25: map[string]AttentionCWE{"2024": {
				Rank: "11",
				URL:  cwe.CweTopTwentyfiveURLs["2024"],
			}},
			wantSans: map[string]AttentionCWE{"2011": {
				Rank: "11",
				URL:  cwe.SansTopTwentyfiveURLs["2011"],
			}},
		},
		{
			name: "ja/Ja-nil falls back to En name + mitre URL",
			c: CWEDict{
				"79": {
					En:                 &cwe.CWE{CWEID: "79", Name: "Cross-site Scripting", Lang: "en"},
					OwaspTopTens:       map[string]string{},
					CweTopTwentyfives:  map[string]string{},
					SansTopTwentyfives: map[string]string{},
				},
			},
			args:      args{cweID: "CWE-79", lang: "ja"},
			wantName:  "Cross-site Scripting",
			wantUrl:   "https://cwe.mitre.org/data/definitions/CWE-79.html",
			wantOwasp: map[string]AttentionCWE{},
			wantCwe25: map[string]AttentionCWE{},
			wantSans:  map[string]AttentionCWE{},
		},
		{
			name: "ja/Ja-non-nil-empty-Name falls back to En name + mitre URL",
			c: CWEDict{
				"22": {
					En:                 &cwe.CWE{CWEID: "22", Name: "Path Traversal", Lang: "en"},
					Ja:                 &cwe.CWE{CWEID: "22", Lang: "ja"},
					OwaspTopTens:       map[string]string{},
					CweTopTwentyfives:  map[string]string{},
					SansTopTwentyfives: map[string]string{},
				},
			},
			args:      args{cweID: "CWE-22", lang: "ja"},
			wantName:  "Path Traversal",
			wantUrl:   "https://cwe.mitre.org/data/definitions/CWE-22.html",
			wantOwasp: map[string]AttentionCWE{},
			wantCwe25: map[string]AttentionCWE{},
			wantSans:  map[string]AttentionCWE{},
		},
		{
			name: "id without CWE- prefix resolves the same entry",
			c: CWEDict{
				"306": {
					En:                 &cwe.CWE{CWEID: "306", Name: "Missing Authentication for Critical Function", Lang: "en"},
					OwaspTopTens:       map[string]string{},
					CweTopTwentyfives:  map[string]string{},
					SansTopTwentyfives: map[string]string{},
				},
			},
			args:     args{cweID: "306", lang: "en"},
			wantName: "Missing Authentication for Critical Function",
			// Get uses the raw input when formatting URL, so the result keeps
			// the input form — documented quirk of the existing API surface.
			wantUrl:   "https://cwe.mitre.org/data/definitions/306.html",
			wantOwasp: map[string]AttentionCWE{},
			wantCwe25: map[string]AttentionCWE{},
			wantSans:  map[string]AttentionCWE{},
		},
		{
			name: "missing entry returns all zero values",
			c:    CWEDict{},
			args: args{cweID: "CWE-999999", lang: "en"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotUrl, gotOwasp, gotCwe25, gotSans := tt.c.Get(tt.args.cweID, tt.args.lang)
			if gotName != tt.wantName {
				t.Errorf("CWEDict.Get() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotUrl != tt.wantUrl {
				t.Errorf("CWEDict.Get() gotUrl = %v, want %v", gotUrl, tt.wantUrl)
			}
			if !reflect.DeepEqual(gotOwasp, tt.wantOwasp) {
				t.Errorf("CWEDict.Get() gotOwasp = %v, want %v", gotOwasp, tt.wantOwasp)
			}
			if !reflect.DeepEqual(gotCwe25, tt.wantCwe25) {
				t.Errorf("CWEDict.Get() gotCwe25 = %v, want %v", gotCwe25, tt.wantCwe25)
			}
			if !reflect.DeepEqual(gotSans, tt.wantSans) {
				t.Errorf("CWEDict.Get() gotSans = %v, want %v", gotSans, tt.wantSans)
			}
		})
	}
}
