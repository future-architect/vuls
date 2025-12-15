//go:build !scanner

package detector

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/cwe"
	"github.com/future-architect/vuls/models"
	cvemodels "github.com/vulsio/go-cve-dictionary/models"
)

func Test_getMaxConfidence(t *testing.T) {
	type args struct {
		detail cvemodels.CveDetail
	}
	tests := []struct {
		name    string
		args    args
		wantMax models.Confidence
	}{
		{
			name: "JvnVendorProductMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{},
					Jvns: []cvemodels.Jvn{{}},
				},
			},
			wantMax: models.JvnVendorProductMatch,
		},
		{
			name: "NvdExactVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdRoughVersionMatch},
						{DetectionMethod: cvemodels.NvdVendorProductMatch},
						{DetectionMethod: cvemodels.NvdExactVersionMatch},
					},
					Jvns: []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
				},
			},
			wantMax: models.NvdExactVersionMatch,
		},
		{
			name: "NvdRoughVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdRoughVersionMatch},
						{DetectionMethod: cvemodels.NvdVendorProductMatch},
					},
					Jvns: []cvemodels.Jvn{},
				},
			},
			wantMax: models.NvdRoughVersionMatch,
		},
		{
			name: "NvdVendorProductMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdVendorProductMatch},
					},
					Vulnchecks: []cvemodels.Vulncheck{{DetectionMethod: cvemodels.VulncheckExactVersionMatch}},
					Jvns:       []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
				},
			},
			wantMax: models.NvdVendorProductMatch,
		},
		{
			name: "VulncheckExactVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Jvns:       []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
					Vulnchecks: []cvemodels.Vulncheck{{DetectionMethod: cvemodels.VulncheckExactVersionMatch}},
				},
			},
			wantMax: models.VulncheckExactVersionMatch,
		},
		{
			name: "FortinetExactVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdExactVersionMatch},
					},
					Jvns:      []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
					Fortinets: []cvemodels.Fortinet{{DetectionMethod: cvemodels.FortinetExactVersionMatch}},
				},
			},
			wantMax: models.FortinetExactVersionMatch,
		},
		{
			name: "PaloaltoExactVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds:      []cvemodels.Nvd{{DetectionMethod: cvemodels.NvdExactVersionMatch}},
					Jvns:      []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
					Paloaltos: []cvemodels.Paloalto{{DetectionMethod: cvemodels.PaloaltoExactVersionMatch}},
				},
			},
			wantMax: models.PaloaltoExactVersionMatch,
		},
		{
			name: "CiscoExactVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds:   []cvemodels.Nvd{{DetectionMethod: cvemodels.NvdExactVersionMatch}},
					Jvns:   []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
					Ciscos: []cvemodels.Cisco{{DetectionMethod: cvemodels.CiscoExactVersionMatch}},
				},
			},
			wantMax: models.CiscoExactVersionMatch,
		},
		{
			name: "empty",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{},
					Jvns: []cvemodels.Jvn{},
				},
			},
			wantMax: models.Confidence{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMax := getMaxConfidence(tt.args.detail); !reflect.DeepEqual(gotMax, tt.wantMax) {
				t.Errorf("getMaxConfidence() = %v, want %v", gotMax, tt.wantMax)
			}
		})
	}
}

func TestFillCweDict(t *testing.T) {
	type args struct {
		r *models.ScanResult
	}
	tests := []struct {
		name string
		args args
		want models.CweDict
	}{
		{
			name: "happy",
			args: args{
				r: &models.ScanResult{
					ScannedCves: models.VulnInfos{
						"CVE-2024-49038": models.VulnInfo{
							CveID: "CVE-2024-49038",
							CveContents: models.CveContents{
								models.Mitre: []models.CveContent{
									{
										Type:   models.Mitre,
										CveID:  "CVE-2024-49038",
										CweIDs: []string{"CWE-79"},
									},
								},
							},
						},
					},
				},
			},
			want: models.CweDict{
				"79": models.CweDictEntry{
					En: &cwe.Cwe{
						CweID:       "79",
						Name:        "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
						Description: "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
						Lang:        "en",
					},
					OwaspTopTens: map[string]string{
						"2017": "7",
						"2021": "3",
					},
					CweTopTwentyfives: map[string]string{
						"2019": "2",
						"2020": "1",
						"2021": "2",
						"2022": "2",
						"2023": "2",
						"2024": "1",
						"2025": "1",
					},
					SansTopTwentyfives: map[string]string{
						"2010":   "1",
						"2011":   "4",
						"latest": "2",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			FillCweDict(tt.args.r)
			if !reflect.DeepEqual(tt.args.r.CweDict, tt.want) {
				t.Errorf("FillCweDict() = %v, want %v", tt.args.r.CweDict, tt.want)
			}
		})
	}
}
