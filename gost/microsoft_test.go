//go:build !scanner

package gost

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	gostmodels "github.com/vulsio/gost/models"
)

func TestMicrosoft_detect(t *testing.T) {
	type args struct {
		r         *models.ScanResult
		cve       gostmodels.MicrosoftCVE
		applied   []string
		unapplied []string
	}
	tests := []struct {
		name    string
		args    args
		want    *models.VulnInfo
		wantErr bool
	}{
		{
			name: "microsoft windows not affected",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows Server 2012 R2",
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2023-21554",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Windows Server 2012 R2",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "5025285",
									FixedBuild: "6.3.9600.20919",
								},
								{
									Article:    "5025288",
									FixedBuild: "6.3.9600.20919",
								},
							},
						},
					},
				},
				applied: []string{"5025288"},
			},
		},
		{
			name: "microsoft windows not affected2",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2023-21554",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Windows 10 Version 21H2 for x64-based Systems",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "5025221",
									FixedBuild: "10.0.19044.2846",
								},
							},
						},
					},
				},
				unapplied: []string{"5026361"},
			},
		},
		{
			name: "microsoft windows fixed",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2023-21554",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Windows 10 Version 21H2 for x64-based Systems",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "5025221",
									FixedBuild: "10.0.19044.2846",
								},
							},
						},
					},
				},
				unapplied: []string{"5025221"},
			},
			want: &models.VulnInfo{
				CveID:       "CVE-2023-21554",
				Confidences: models.Confidences{models.WindowsUpdateSearch},
				DistroAdvisories: models.DistroAdvisories{
					{
						AdvisoryID:  "KB5025221",
						Description: "Microsoft Knowledge Base",
					},
				},
				CveContents: models.CveContents{
					models.Microsoft: []models.CveContent{
						{
							Type:  models.Microsoft,
							CveID: "CVE-2023-21554",
						},
					},
				},
				WindowsKBFixedIns: []string{"KB5025221"},
			},
		},
		{
			name: "microsoft windows unfixed",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2013-3900",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Windows 10 Version 21H2 for x64-based Systems",
						},
					},
				},
			},
			want: &models.VulnInfo{
				CveID:       "CVE-2013-3900",
				Confidences: models.Confidences{models.WindowsUpdateSearch},
				AffectedPackages: models.PackageFixStatuses{
					{
						Name:     "Windows 10 Version 21H2 for x64-based Systems",
						FixState: "unfixed",
					},
				},
				CveContents: models.CveContents{
					models.Microsoft: []models.CveContent{
						{
							Type:  models.Microsoft,
							CveID: "CVE-2013-3900",
						},
					},
				},
			},
		},
		{
			name: "microsoft edge not installed",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2024-8639",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Microsoft Edge (Chromium-based)",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "Release Notes",
									FixedBuild: "128.0.2739.79",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft edge not affected",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Packages: models.Packages{
						"Microsoft Edge": {
							Name:    "Microsoft Edge",
							Version: "128.0.2739.79",
						},
					},
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2024-8639",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Microsoft Edge (Chromium-based)",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "Release Notes",
									FixedBuild: "128.0.2739.79",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft edge fixed",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows Server 2016",
					Packages: models.Packages{
						"Microsoft Edge": {
							Name:    "Microsoft Edge",
							Version: "38.14393",
						},
					},
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2016-7195",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Internet Explorer 11 on Windows Server 2016",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article: "3200970",
								},
							},
						},
						{
							Name: "Microsoft Edge (EdgeHTML-based) on Windows Server 2016",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article: "3200970",
								},
							},
						},
					},
				},
				unapplied: []string{"3200970"},
			},
			want: &models.VulnInfo{
				CveID:       "CVE-2016-7195",
				Confidences: models.Confidences{models.WindowsUpdateSearch},
				DistroAdvisories: models.DistroAdvisories{
					{
						AdvisoryID:  "KB3200970",
						Description: "Microsoft Knowledge Base",
					},
				},
				CveContents: models.CveContents{
					models.Microsoft: []models.CveContent{
						{
							Type:  models.Microsoft,
							CveID: "CVE-2016-7195",
						},
					},
				},
				WindowsKBFixedIns: []string{"KB3200970"},
			},
		},
		{
			name: "microsoft edge fixed2",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Packages: models.Packages{
						"Microsoft Edge": {
							Name:    "Microsoft Edge",
							Version: "111.0.1661.41",
						},
					},
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2024-8639",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Microsoft Edge (Chromium-based)",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "Release Notes",
									FixedBuild: "128.0.2739.79",
								},
							},
						},
					},
				},
			},
			want: &models.VulnInfo{
				CveID:       "CVE-2024-8639",
				Confidences: models.Confidences{models.WindowsUpdateSearch},
				AffectedPackages: models.PackageFixStatuses{
					{
						Name:     "Microsoft Edge",
						FixState: "fixed",
						FixedIn:  "128.0.2739.79",
					},
				},
				CveContents: models.CveContents{
					models.Microsoft: []models.CveContent{
						{
							Type:  models.Microsoft,
							CveID: "CVE-2024-8639",
						},
					},
				},
			},
		},
		{
			name: "microsoft edge unknown",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Packages: models.Packages{
						"Microsoft Edge": {
							Name:    "Microsoft Edge",
							Version: "111.0.1661.41",
						},
					},
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2020-1195",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Microsoft Edge (Chromium-based)",
						},
					},
				},
			},
			want: &models.VulnInfo{
				CveID:       "CVE-2020-1195",
				Confidences: models.Confidences{models.WindowsRoughMatch},
				AffectedPackages: models.PackageFixStatuses{
					{
						Name:     "Microsoft Edge",
						FixState: "unknown",
					},
				},
				CveContents: models.CveContents{
					models.Microsoft: []models.CveContent{
						{
							Type:  models.Microsoft,
							CveID: "CVE-2020-1195",
						},
					},
				},
			},
		},
		{
			name: "microsoft edge unknown2",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Packages: models.Packages{
						"Microsoft Edge": {
							Name:    "Microsoft Edge",
							Version: "111.0.1661.41",
						},
					},
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2022-4135",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Microsoft Edge (Chromium-based)",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article: "Release Notes",
								},
							},
						},
					},
				},
			},
			want: &models.VulnInfo{
				CveID:       "CVE-2022-4135",
				Confidences: models.Confidences{models.WindowsRoughMatch},
				AffectedPackages: models.PackageFixStatuses{
					{
						Name:     "Microsoft Edge",
						FixState: "unknown",
					},
				},
				CveContents: models.CveContents{
					models.Microsoft: []models.CveContent{
						{
							Type:  models.Microsoft,
							CveID: "CVE-2022-4135",
						},
					},
				},
			},
		},
		{
			name: "microsoft other product not support",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Packages: models.Packages{
						"Microsoft Visual Studio Code": {
							Name:    "Microsoft Visual Studio Code",
							Version: "1.76.0",
						},
					},
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "CVE-2024-26165",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Visual Studio Code",
							KBs: []gostmodels.MicrosoftKB{
								{
									Article:    "Release Notes",
									FixedBuild: "1.87.2",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft other product not support2",
			args: args{
				r: &models.ScanResult{
					Family:  constant.Windows,
					Release: "Windows Server 2016",
				},
				cve: gostmodels.MicrosoftCVE{
					CveID: "ADV200001",
					Products: []gostmodels.MicrosoftProduct{
						{
							Name: "Internet Explorer 11 on Windows Server 2016",
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (Microsoft{}).detect(tt.args.r, tt.args.cve, tt.args.applied, tt.args.unapplied)
			if (err != nil) != tt.wantErr {
				t.Errorf("Microsoft.detect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Microsoft.detect() = %v, want %v", got, tt.want)
			}
		})
	}
}
