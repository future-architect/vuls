package vuls2_test

import (
	"cmp"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	cpecriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	cpecRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	kbcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	versioncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	exploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/exploit"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	cvssV40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"

	"github.com/future-architect/vuls/detector/vuls2"
	testutil "github.com/future-architect/vuls/detector/vuls2/internal/test"
	"github.com/future-architect/vuls/models"
)

func Test_preConvert(t *testing.T) {
	type args struct {
		sr      *models.ScanResult
		cpeOnly bool
	}
	tests := []struct {
		name string
		args args
		want scanTypes.ScanResult
	}{
		{
			name: "ubuntu 22.04, old scanner",
			args: args{
				sr: &models.ScanResult{
					ServerName: "jammy",
					Family:     "ubuntu",
					Release:    "22.04",
					RunningKernel: models.Kernel{
						Release:        "5.15.0-144-generic",
						Version:        "",
						RebootRequired: true,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name: "cron",
						},
					},
					SrcPackages: models.SrcPackages{
						"cron": models.SrcPackage{
							Name:        "cron",
							Version:     "3.0pl1-137ubuntu3",
							BinaryNames: []string{"cron"},
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "jammy",
				Family:      ecosystemTypes.Ecosystem("ubuntu"),
				Release:     "22.04",

				Kernel: scanTypes.Kernel{
					Release:        "5.15.0-144-generic",
					Version:        "",
					RebootRequired: true,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:       "cron",
						Version:    "0",
						SrcName:    "cron",
						SrcVersion: "3.0pl1-137ubuntu3",
					},
				},
			},
		},
		{
			name: "ubuntu 22.04",
			args: args{
				sr: &models.ScanResult{
					ServerName: "jammy",
					Family:     "ubuntu",
					Release:    "22.04",
					RunningKernel: models.Kernel{
						Release:        "5.15.0-144-generic",
						Version:        "",
						RebootRequired: true,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "cron",
							Version: "3.0pl1-137ubuntu3",
						},
					},
					SrcPackages: models.SrcPackages{
						"cron": models.SrcPackage{
							Name:        "cron",
							Version:     "3.0pl1-137ubuntu3",
							BinaryNames: []string{"cron"},
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "jammy",
				Family:      ecosystemTypes.Ecosystem("ubuntu"),
				Release:     "22.04",

				Kernel: scanTypes.Kernel{
					Release:        "5.15.0-144-generic",
					Version:        "",
					RebootRequired: true,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:       "cron",
						Version:    "3.0pl1-137ubuntu3",
						SrcName:    "cron",
						SrcVersion: "3.0pl1-137ubuntu3",
					},
				},
			},
		},
		{
			name: "suse.linux.enterprise.server -> suse.linux.enterprise",
			args: args{
				sr: &models.ScanResult{
					ServerName: "sles-15",
					Family:     "suse.linux.enterprise.server",
					Release:    "15.3",
					RunningKernel: models.Kernel{
						Release:        "5.3.18-59.37-default",
						Version:        "",
						RebootRequired: false,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "sles-release",
							Version: "15.3",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "sles-15",
				Family:      ecosystemTypes.Ecosystem("suse.linux.enterprise"),
				Release:     "15.3",

				Kernel: scanTypes.Kernel{
					Release:        "5.3.18-59.37-default",
					Version:        "",
					RebootRequired: false,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "sles-release",
						Version: "15.3",
					},
				},
			},
		},
		{
			name: "suse.linux.enterprise.desktop -> suse.linux.enterprise",
			args: args{
				sr: &models.ScanResult{
					ServerName: "sled-15",
					Family:     "suse.linux.enterprise.desktop",
					Release:    "15.3",
					RunningKernel: models.Kernel{
						Release:        "5.3.18-59.37-default",
						Version:        "",
						RebootRequired: false,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "sled-release",
							Version: "15.3",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "sled-15",
				Family:      ecosystemTypes.Ecosystem("suse.linux.enterprise"),
				Release:     "15.3",

				Kernel: scanTypes.Kernel{
					Release:        "5.3.18-59.37-default",
					Version:        "",
					RebootRequired: false,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "sled-release",
						Version: "15.3",
					},
				},
			},
		},
		{
			name: "opensuse:tumbleweed",
			args: args{
				sr: &models.ScanResult{
					ServerName: "tumbleweed",
					Family:     "opensuse",
					Release:    "tumbleweed",
					RunningKernel: models.Kernel{
						Release:        "5.3.18-59.37-default",
						Version:        "",
						RebootRequired: false,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "openSUSE-release",
							Version: "20210101",
							Release: "0",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "tumbleweed",
				Family:      ecosystemTypes.EcosystemTypeOpenSUSETumbleweed,

				Kernel: scanTypes.Kernel{
					Release:        "5.3.18-59.37-default",
					Version:        "",
					RebootRequired: false,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "openSUSE-release",
						Version: "20210101",
						Release: "0",
					},
				},
			},
		},
		{
			name: "amazon linux 2, old scanner with codename suffix",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2",
					Family:     "amazon",
					Release:    "2 (Karoo)",
					RunningKernel: models.Kernel{
						Release: "5.10.0-amzn2.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.7",
							Release: "19.amzn2.0.3",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2",

				Kernel: scanTypes.Kernel{
					Release: "5.10.0-amzn2.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.7",
						Release: "19.amzn2.0.3",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 2022, old scanner with codename suffix",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2022",
					Family:     "amazon",
					Release:    "2022 (Amazon Linux)",
					RunningKernel: models.Kernel{
						Release: "5.15.0-amzn2022.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.11",
							Release: "31.amzn2022.0.3",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2022",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2022",

				Kernel: scanTypes.Kernel{
					Release: "5.15.0-amzn2022.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.11",
						Release: "31.amzn2022.0.3",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 2023, new scanner",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2023",
					Family:     "amazon",
					Release:    "2023.3.20240312",
					RunningKernel: models.Kernel{
						Release: "6.1.0-amzn2023.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.13",
							Release: "1.amzn2023.0.1",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2023",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2023",

				Kernel: scanTypes.Kernel{
					Release: "6.1.0-amzn2023.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.13",
						Release: "1.amzn2023.0.1",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 1, old scanner with date-style release",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al1",
					Family:     "amazon",
					Release:    "2018.03",
					RunningKernel: models.Kernel{
						Release: "4.14.0-amzn1.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.8",
							Release: "10.32.amzn1",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al1",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "1",

				Kernel: scanTypes.Kernel{
					Release: "4.14.0-amzn1.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.8",
						Release: "10.32.amzn1",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 2, new scanner",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2",
					Family:     "amazon",
					Release:    "2",
					RunningKernel: models.Kernel{
						Release: "5.10.0-amzn2.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.7",
							Release: "19.amzn2.0.3",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2",

				Kernel: scanTypes.Kernel{
					Release: "5.10.0-amzn2.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.7",
						Release: "19.amzn2.0.3",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "windows -> microsoft with WindowsKB",
			args: args{
				sr: &models.ScanResult{
					ServerName: "win-server",
					Family:     "windows",
					Release:    "Windows 10 Version 21H2 for x64-based Systems",
					RunningKernel: models.Kernel{
						Version: "10.0.19044.1234",
					},
					WindowsKB: &models.WindowsKB{
						Applied:   []string{"5025288"},
						Unapplied: []string{"5025221"},
					},
					Packages: models.Packages{
						"Microsoft Edge": models.Package{
							Name:    "Microsoft Edge",
							Version: "128.0.2739.79",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "win-server",
				Family:      ecosystemTypes.EcosystemTypeMicrosoft,
				Release:     "Windows 10 Version 21H2 for x64-based Systems",

				Kernel: scanTypes.Kernel{
					Version: "10.0.19044.1234",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "Microsoft Edge",
						Version: "128.0.2739.79",
					},
					{
						Name:    "Windows 10 Version 21H2 for x64-based Systems",
						Version: "10.0.19044.1234",
					},
				},
				MicrosoftKB: scanTypes.MicrosoftKB{
					Applied:   []string{"5025288"},
					Unapplied: []string{"5025221"},
				},
			},
		},
		{
			name: "windows without WindowsKB (nil)",
			args: args{
				sr: &models.ScanResult{
					ServerName: "win-server-no-kb",
					Family:     "windows",
					Release:    "Windows Server 2019",
					RunningKernel: models.Kernel{
						Version: "10.0.17763.1234",
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "win-server-no-kb",
				Family:      ecosystemTypes.EcosystemTypeMicrosoft,
				Release:     "Windows Server 2019",

				Kernel: scanTypes.Kernel{
					Version: "10.0.17763.1234",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "Windows Server 2019",
						Version: "10.0.17763.1234",
					},
				},
			},
		},
		{
			// cpeOnly suppresses the OS-package / Microsoft-KB inputs even
			// when the scan result carries them (the CPE pass runs after
			// DetectPkgs already handled packages).
			name: "cpeOnly suppresses packages and KB",
			args: args{
				sr: &models.ScanResult{
					ServerName: "win-server",
					Family:     "windows",
					Release:    "Windows Server 2019",
					RunningKernel: models.Kernel{
						Version: "10.0.17763.1234",
					},
					Packages: models.Packages{
						"package1": {Name: "package1", Version: "0.0.1"},
					},
					WindowsKB: &models.WindowsKB{
						Applied:   []string{"0000001"},
						Unapplied: []string{"0000002"},
					},
				},
				cpeOnly: true,
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "win-server",
				Family:      ecosystemTypes.EcosystemTypeMicrosoft,
				Release:     "Windows Server 2019",

				Kernel: scanTypes.Kernel{
					Version: "10.0.17763.1234",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got scanTypes.ScanResult
			if tt.args.cpeOnly {
				got, _ = vuls2.PreConvertCPEs(tt.args.sr, nil)
			} else {
				got = vuls2.PreConvertPkgs(tt.args.sr)
			}
			if diff := gocmp.Diff(got, tt.want, gocmpopts.IgnoreFields(scanTypes.ScanResult{}, "ScannedAt", "ScannedBy")); diff != "" {
				t.Errorf("preConvert() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_postConvert(t *testing.T) {
	type args struct {
		scanned         scanTypes.ScanResult
		detected        detectTypes.DetectResult
		fsToOriginalCPE map[string][]string
	}
	tests := []struct {
		name    string
		args    args
		want    models.VulnInfos
		wantErr bool
	}{
		{
			name: "redhat oval",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package3",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0002",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0002"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0002",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0003"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv2,
																CVSSv2: new(cvssV2Types.CVSSv2{
																	Vector:                   "AV:L/AC:L/Au:N/C:C/I:N/A:C",
																	BaseScore:                6.6,
																	NVDBaseSeverity:          "MEDIUM",
																	TemporalScore:            6.6,
																	NVDTemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:       6.6,
																	NVDEnvironmentalSeverity: "MEDIUM",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv30,
																CVSSv30: new(cvssV30Types.CVSSv30{
																	Vector:                "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package3",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{2},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0003"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv2,
																CVSSv2: new(cvssV2Types.CVSSv2{
																	Vector:                   "AV:L/AC:L/Au:N/C:C/I:N/A:C",
																	BaseScore:                6.6,
																	NVDBaseSeverity:          "MEDIUM",
																	TemporalScore:            6.6,
																	NVDTemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:       6.6,
																	NVDEnvironmentalSeverity: "MEDIUM",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv30,
																CVSSv30: new(cvssV30Types.CVSSv30{
																	Vector:                "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Affected",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package3",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{2},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "CRITICAL",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID:       "CVE-2025-0002",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
						{
							Name:        "package3",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "CRITICAL",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
						{
							AdvisoryID:  "RHSA-2025:0002",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0002",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    7.1,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0002",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0002",
										Source: "REDHAT",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0002",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0002",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}},{\"root_id\":\"RHSA-2025:0002\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0003": {
					CveID:       "CVE-2025-0003",
					Confidences: models.Confidences{models.OvalMatch},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0002",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
						{
							Name:        "package3",
							NotFixedYet: true,
							FixState:    "Affected",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:           models.RedHat,
								CveID:          "CVE-2025-0003",
								Title:          "title",
								Summary:        "description",
								Cvss2Score:     6.6,
								Cvss2Vector:    "AV:L/AC:L/Au:N/C:C/I:N/A:C",
								Cvss2Severity:  "MEDIUM",
								Cvss3Score:     7.1,
								Cvss3Vector:    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity:  "HIGH",
								Cvss40Score:    7.1,
								Cvss40Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
								Cvss40Severity: "HIGH",
								SourceLink:     "https://access.redhat.com/security/cve/CVE-2025-0003",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0003",
										Source: "REDHAT",
										RefID:  "CVE-2025-0003",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0002",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0002",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0003\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}},{\"root_id\":\"RHSA-2025:0002\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat vex",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("MEDIUM"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("HIGH"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1234560-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:2345601-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1234560-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:2345601-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:1234560-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:2345601-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0002",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0002"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:6543210-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("HIGH"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("MEDIUM"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1065432-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "RHSA-2025:0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0002"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("HIGH"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:6543210-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1065432-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:6543210-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-2.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-2.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-2.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-2.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:1065432-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "MEDIUM",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID:       "CVE-2025-0002",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-2.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "HIGH",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
						{
							AdvisoryID:  "RHSA-2025:0002",
							Severity:    "HIGH",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:           models.RedHat,
								CveID:          "CVE-2025-0002",
								Title:          "title",
								Summary:        "description",
								Cvss3Score:     5.5,
								Cvss3Vector:    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity:  "MEDIUM",
								Cvss40Score:    7.1,
								Cvss40Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
								Cvss40Severity: "HIGH",
								SourceLink:     "https://access.redhat.com/security/cve/CVE-2025-0002",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0002",
										Source: "REDHAT",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0002",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0002",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0002\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7\"}},{\"root_id\":\"CVE-2025-0002\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat oval + redhat vex",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID:       "CVE-2025-0002",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "CRITICAL",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0002",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0002",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0002",
										Source: "REDHAT",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat vex + epel + cpe",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
					CPE: []string{
						"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
					},
				},
				// The detection ran on the FS form; the reverse map restores
				// every user-supplied form in VulnInfo.CpeURIs — here the
				// same CPE was configured in both URI and FS form.
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:0.0.0", "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://www.cve.org/CVERecord?id=CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														// NVD extractors lift "Exploit" / "Mitigation"
														// reference tags into these content slots; the
														// detector maps them to models.Exploit /
														// models.Mitigation (NVD content only).
														Mitigations: []remediationTypes.Remediation{
															{
																Source:      "nvd.nist.gov",
																Description: "https://example.com/mitigation",
															},
														},
														Exploit: []exploitTypes.Exploit{
															{
																Source: "nvd.nist.gov",
																Link:   "https://example.com/exploit",
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Affected",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "package",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: cpecriterionTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							ID: "FEDORA-EPEL-2025-0123456789",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FEDORA-EPEL-2025-0123456789",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "FEDORA-EPEL-2025-0123456789",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("MEDIUM"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://www.cve.org/CVERecord?id=CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://www.cve.org/CVERecord?id=CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.FedoraAPI: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID: "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch, models.NvdExactVersionMatch, models.Confidence{
						Score:           100,
						DetectionMethod: models.DetectionMethod("EPELMatch"),
						SortOrder:       1,
					}},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: true,
							FixState:    "Affected",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "FEDORA-EPEL-2025-0123456789",
							Severity:    "MEDIUM",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CpeURIs: []string{"cpe:/a:vendor:product:0.0.0", "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeNVD,
							URL:         "https://example.com/exploit",
						},
					},
					Mitigations: []models.Mitigation{
						{
							CveContentType: models.Nvd,
							URL:            "https://example.com/mitigation",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
						models.Nvd: []models.CveContent{
							{
								Type:          models.Nvd,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
										Source: "NVD",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
						"epel": []models.CveContent{
							{
								Type:          "epel",
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    7.1,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity: "HIGH",
								References: models.References{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0001",
										Source: "CVE",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://bodhi.fedoraproject.org/updates/FEDORA-EPEL-2025-0123456789",
										Source: "FEDORA",
										RefID:  "FEDORA-EPEL-2025-0123456789",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FEDORA-EPEL-2025-0123456789\",\"source_id\":\"fedora-api\",\"segment\":{\"ecosystem\":\"epel:9\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID: "CVE-2025-0002",
					Confidences: models.Confidences{models.Confidence{
						Score:           100,
						DetectionMethod: models.DetectionMethod("EPELMatch"),
						SortOrder:       1,
					}},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "FEDORA-EPEL-2025-0123456789",
							Severity:    "MEDIUM",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						"epel": []models.CveContent{
							{
								Type:          "epel",
								CveID:         "CVE-2025-0002",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    7.1,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity: "HIGH",
								References: models.References{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0002",
										Source: "CVE",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://bodhi.fedoraproject.org/updates/FEDORA-EPEL-2025-0123456789",
										Source: "FEDORA",
										RefID:  "FEDORA-EPEL-2025-0123456789",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FEDORA-EPEL-2025-0123456789\",\"source_id\":\"fedora-api\",\"segment\":{\"ecosystem\":\"epel:9\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// No criterion accepts, but a vulnerable=true criterion with no
			// version information (version NA) matched on
			// part:vendor:product — the CVE is reported with the low
			// NvdVendorProductMatch confidence (mirroring
			// go-cve-dictionary's VendorProductMatch). Criterions with a
			// different vendor:product, with vulnerable=false (hardware
			// guards), or whose range confirms the query is out of range do
			// not contribute.
			name: "cpe vendor:product fallback",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:9.9.9"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// same vendor:product, version NA -> fallback hit
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: cpecriterionTypes.CPE("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"),
																}),
															},
														},
														{
															// same vendor:product but the range confirms the
															// scanned 9.9.9 is out of range -> no contribution
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: cpecriterionTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
																	Range: new(cpecRangeTypes.Range{
																		Type:     cpecRangeTypes.RangeTypeSEMVER,
																		LessThan: "5.0",
																	}),
																}),
															},
														},
														{
															// different vendor:product -> no contribution
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: cpecriterionTypes.CPE("cpe:2.3:a:othervendor:otherproduct:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
														},
														{
															// vulnerable=false (hardware guard) -> excluded
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: false,
																	CPE:        cpecriterionTypes.CPE("cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*"),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0003": {
					CveID:       "CVE-2025-0003",
					Confidences: models.Confidences{models.NvdVendorProductMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:9.9.9"},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:       models.Nvd,
								CveID:      "CVE-2025-0003",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2025-0003",
								References: models.References{
									{
										Link:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0003",
										Source: "NVD",
										RefID:  "CVE-2025-0003",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0003\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// The vendor:product fallback honours AND structure: a CVE whose
			// configuration requires product A AND product B is not reported
			// when only A was scanned.
			name: "cpe vendor:product fallback, unsatisfied AND",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:producta:9.9.9"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0004",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeAND,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	CPE:        cpecriterionTypes.CPE("cpe:2.3:a:vendor:producta:-:*:*:*:*:*:*:*"),
																}),
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	CPE:        cpecriterionTypes.CPE("cpe:2.3:a:vendor:productb:-:*:*:*:*:*:*:*"),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			// Same AND configuration with both products scanned: the fallback
			// fires and reports both CPEs at VendorProductMatch.
			name: "cpe vendor:product fallback, satisfied AND",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*",
						"cpe:2.3:a:vendor:productb:8.8.8:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:producta:9.9.9"},
					"cpe:2.3:a:vendor:productb:8.8.8:*:*:*:*:*:*:*": {"cpe:/a:vendor:productb:8.8.8"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0004",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeAND,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	CPE:        cpecriterionTypes.CPE("cpe:2.3:a:vendor:producta:-:*:*:*:*:*:*:*"),
																}),
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	CPE:        cpecriterionTypes.CPE("cpe:2.3:a:vendor:productb:-:*:*:*:*:*:*:*"),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0004": {
					CveID:       "CVE-2025-0004",
					Confidences: models.Confidences{models.NvdVendorProductMatch},
					CpeURIs:     []string{"cpe:/a:vendor:producta:9.9.9", "cpe:/a:vendor:productb:8.8.8"},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:         models.Nvd,
								CveID:        "CVE-2025-0004",
								Title:        "title",
								Summary:      "description",
								SourceLink:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0004",
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0004\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// The scanned version (21.4r3, the juniper joined form) cannot
			// be compared by the range's semver comparator; mirroring
			// go-cve-dictionary's matchRpmVer fallback, the bound is
			// re-evaluated RPM-style (21.4r3 < 22.2 holds) and the CVE is
			// reported at VendorProductMatch instead of disappearing.
			name: "cpe vendor:product fallback, range incomparable -> rpm fallback",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:o:vendor:product:21.4r3:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:o:vendor:product:21.4r3:*:*:*:*:*:*:*": {"cpe:/o:vendor:product:21.4r3"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0005",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0005",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0005"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0005",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(cpecriterionTypes.Criterion{
																	Vulnerable: true,
																	CPE:        cpecriterionTypes.CPE("cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*"),
																	Range: new(cpecRangeTypes.Range{
																		Type:     cpecRangeTypes.RangeTypeSEMVER,
																		LessThan: "22.2",
																	}),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0005": {
					CveID:       "CVE-2025-0005",
					Confidences: models.Confidences{models.NvdVendorProductMatch},
					CpeURIs:     []string{"cpe:/o:vendor:product:21.4r3"},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:         models.Nvd,
								CveID:        "CVE-2025-0005",
								Title:        "title",
								Summary:      "description",
								SourceLink:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0005",
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0005\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat ignore pattern",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "kpatch-patch-1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeNoneExist,
																		NoneExist: new(noneexistcriterionTypes.Criterion{
																			Type: noneexistcriterionTypes.PackageTypeBinary,
																			Binary: &necBinaryPackageTypes.Package{
																				Name:          "kpatch-patch-2",
																				Architectures: []string{"aarch64", "x86_64"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		NoneExist: true,
																	},
																},
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeVersion,
																		Version: new(versioncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: new(vcFixStatusTypes.FixStatus{
																				Class: vcFixStatusTypes.ClassFixed,
																			}),
																			Package: vcPackageTypes.Package{
																				Type: vcPackageTypes.PackageTypeBinary,
																				Binary: &vcBinaryPackageTypes.Package{
																					Name:          "package1",
																					Architectures: []string{"aarch64", "x86_64"},
																				},
																			},
																			Affected: &vcAffectedTypes.Affected{
																				Type: vcAffectedRangeTypes.RangeTypeRPM,
																				Range: []vcAffectedRangeTypes.Range{
																					{
																						LessThan: "0.0.0-1.el9",
																					},
																				},
																				Fixed: []string{"0.0.0-1.el9"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		Version: []int{0},
																	},
																},
															},
														},
														{
															Operator: criteriaTypes.CriteriaOperatorTypeOR,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeVersion,
																		Version: new(versioncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: new(vcFixStatusTypes.FixStatus{
																				Class: vcFixStatusTypes.ClassFixed,
																			}),
																			Package: vcPackageTypes.Package{
																				Type: vcPackageTypes.PackageTypeBinary,
																				Binary: &vcBinaryPackageTypes.Package{
																					Name:          "kpatch-patch-1",
																					Architectures: []string{"aarch64", "x86_64"},
																				},
																			},
																			Affected: &vcAffectedTypes.Affected{
																				Type: vcAffectedRangeTypes.RangeTypeRPM,
																				Range: []vcAffectedRangeTypes.Range{
																					{
																						LessThan: "0.0.0-1.el9",
																					},
																				},
																				Fixed: []string{"0.0.0-1.el9"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		Version: []int{1},
																	},
																},
															},
														},
														{
															Operator: criteriaTypes.CriteriaOperatorTypeOR,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeVersion,
																		Version: new(versioncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: new(vcFixStatusTypes.FixStatus{
																				Class: vcFixStatusTypes.ClassFixed,
																			}),
																			Package: vcPackageTypes.Package{
																				Type: vcPackageTypes.PackageTypeBinary,
																				Binary: &vcBinaryPackageTypes.Package{
																					Name:          "package1",
																					Architectures: []string{"aarch64", "x86_64"},
																				},
																			},
																			Affected: &vcAffectedTypes.Affected{
																				Type: vcAffectedRangeTypes.RangeTypeRPM,
																				Range: []vcAffectedRangeTypes.Range{
																					{
																						LessThan: "0.0.0-0.el9_1",
																					},
																				},
																				Fixed: []string{"0.0.0-0.el9_1"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		Version: []int{0},
																	},
																},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0002",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0002"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0002",
														Title:       "title",
														Description: "** REJECT ** description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0002"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0003",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0003"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0003",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "** REJECT ** description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0004",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0004",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0004"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0004",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0004",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0005",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0005",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0005"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0005",
														Title:       "title",
														Description: "** REJECT ** description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0005",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Affected",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0006",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0006",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0006"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0006",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0006",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Will not fix",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0007",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0007",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0007"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0007",
														Title:       "title",
														Description: "[REJECTED CVE] description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0007",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:gfedcba-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:gfedcba-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-0.el9_1",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:       models.RedHat,
								CveID:      "CVE-2025-0001",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0003": {
					CveID:       "CVE-2025-0003",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0003",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:       models.RedHat,
								CveID:      "CVE-2025-0003",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://access.redhat.com/security/cve/CVE-2025-0003",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0003",
										Source: "REDHAT",
										RefID:  "CVE-2025-0003",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0003",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0003",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0003\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0004": {
					CveID:       "CVE-2025-0004",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0004",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:       models.RedHat,
								CveID:      "CVE-2025-0004",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://access.redhat.com/security/cve/CVE-2025-0004",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0004",
										Source: "REDHAT",
										RefID:  "CVE-2025-0004",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0004",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0004",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0004\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "alma",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "ALSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "ALSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.AlmaErrata: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "ALSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOVAL: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "ALSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOSV: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "ALSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.AlmaErrata: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOVAL: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOSV: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.AlmaErrata: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
										sourceTypes.AlmaOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
										sourceTypes.AlmaOSV: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "ALSA-2025:0001",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.Alma: []models.CveContent{
							{
								Type:    models.Alma,
								CveID:   "CVE-2025-0001",
								Title:   "title",
								Summary: "description",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://errata.almalinux.org/9/ALSA-2025-0001.html",
										Source: "ALMA",
										RefID:  "ALSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"ALSA-2025:0001\",\"source_id\":\"alma-errata\",\"segment\":{\"ecosystem\":\"alma:9\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "rocky",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RLSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RLSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RockyErrata: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RLSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
										sourceTypes.RockyOSV: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RLSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RockyErrata: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
										sourceTypes.RockyOSV: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RockyErrata: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
										sourceTypes.RockyOSV: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RLSA-2025:0001",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.Rocky: []models.CveContent{
							{
								Type:    models.Rocky,
								CveID:   "CVE-2025-0001",
								Title:   "title",
								Summary: "description",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://errata.build.resf.org/RLSA-2025:0001",
										Source: "ROCKY",
										RefID:  "RLSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RLSA-2025:0001\",\"source_id\":\"rocky-errata\",\"segment\":{\"ecosystem\":\"rocky:9\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ubuntu",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.15.0-69-generic",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "linux-headers-5.15.0-69",
							Version:    "5.15.0-69.76",
							SrcName:    "linux",
							SrcVersion: "5.15.0-69.76",
						},
						{
							Name:       "linux-headers-5.15.0-69-generic",
							Version:    "5.15.0-69.76",
							SrcName:    "linux",
							SrcVersion: "5.15.0-69.76",
						},
						{
							Name:       "linux-headers-generic",
							Version:    "5.15.0.69.67",
							SrcName:    "linux-meta",
							SrcVersion: "5.15.0.69.67",
						},
						{
							Name:       "linux-image-5.15.0-69-generic",
							Version:    "5.15.0-69.76",
							SrcName:    "linux-signed",
							SrcVersion: "5.15.0-69.76",
						},
						{
							Name:       "linux-image-5.15.0-33-generic",
							Version:    "5.15.0-33.34",
							SrcName:    "linux-signed",
							SrcVersion: "5.15.0-33.34",
						},
						{
							Name:       "linux-image-virtual",
							Version:    "5.15.0.69.67",
							SrcName:    "linux-meta",
							SrcVersion: "5.15.0.69.67",
						},
						{
							Name:       "bash",
							Version:    "5.1-6ubuntu1",
							SrcName:    "bash",
							SrcVersion: "5.1-6ubuntu1",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0002",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0002"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "** REJECT ** description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "Rejected reason: description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0004",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0004",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "ignored: end of kernel support",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 2, 3, 4, 5},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0005",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0005",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0005"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0005",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0005",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "fips-updates/jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77+fips.1",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77+fips.1"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "fips-updates/jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0006",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0006",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0006"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0006",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0006",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "esm-apps/jammy_low",
														},
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "fips-updates/jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77+esm.1",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77+esm.1"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "esm-apps/jammy_low",
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77+fips.1",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77+fips.1"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "fips-updates/jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0007",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0007",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0007"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0007",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0007",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-69.76",
																			},
																		},
																		Fixed: []string{"5.15.0-69.76"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0008",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0008",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0008"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0008",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0008",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.1-6ubuntu2",
																			},
																		},
																		Fixed: []string{"5.1-6ubuntu2"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{6},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "linux-headers-5.15.0-69",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-headers-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-image-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-0001",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0001",
										Source: "CVE",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0006": {
					CveID:       "CVE-2025-0006",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "linux-headers-5.15.0-69",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-headers-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-image-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-0006",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-0006",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0006",
										Source: "CVE",
										RefID:  "CVE-2025-0006",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0006\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0008": {
					CveID:       "CVE-2025-0008",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "bash",
							NotFixedYet: false,
							FixedIn:     "5.1-6ubuntu2",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-0008",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-0008",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0008",
										Source: "CVE",
										RefID:  "CVE-2025-0008",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0008\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ubuntu needs-triage and not-affected should be filtered by vulnerable:false",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "bash",
							Version:    "5.1-6ubuntu1",
							SrcName:    "bash",
							SrcVersion: "5.1-6ubuntu1",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-1001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-1001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-1001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-1001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-1001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.1-6ubuntu2",
																			},
																		},
																		Fixed: []string{"5.1-6ubuntu2"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							// needs-triage: vulnerable=false, should NOT be detected
							ID: "CVE-2025-1002",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-1002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-1002"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-1002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("medium"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-1002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_medium",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// needs-triage: Vulnerable=false, Affected=nil
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: false,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnknown,
																		Vendor: "needs-triage",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: "jammy_medium",
											},
										},
									},
								},
							},
						},
						{
							// not-affected: vulnerable=false, should NOT be detected
							ID: "CVE-2025-1003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-1003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-1003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-1003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("medium"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-1003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_medium",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// not-affected: Vulnerable=false, Affected=nil
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: false,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassNotAffected,
																		Vendor: "not-affected: code not present",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: "jammy_medium",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			// Only CVE-2025-1001 (vulnerable:true) should appear.
			// CVE-2025-1002 (needs-triage, vulnerable:false) and CVE-2025-1003 (not-affected, vulnerable:false) should be filtered out.
			want: models.VulnInfos{
				"CVE-2025-1001": {
					CveID:       "CVE-2025-1001",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "bash",
							NotFixedYet: false,
							FixedIn:     "5.1-6ubuntu2",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-1001",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-1001",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-1001",
										Source: "CVE",
										RefID:  "CVE-2025-1001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-1001\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "oracle",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.4.17-2102.200.13.el7uek.x86_64",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-tools",
							Version: "3.10.0",
							Release: "1160.24.1.el7",
							Arch:    "x86_64",
						},
						{
							Name:    "kernel-uek",
							Version: "5.4.17",
							Release: "2102.200.13.el7uek",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "ELSA-2022-7337",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "ELSA-2022-7337",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2022-7337"): {
												{
													Content: advisoryContentTypes.Content{
														ID: "ELSA-2022-7337",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-29901",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2022-7337"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2022-29901",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv30,
																CVSSv30: new(cvssV30Types.CVSSv30{
																	Vector:                "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
																	BaseScore:             5.6,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.6,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.6,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.Oracle: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "kernel-tools",
																			Architectures: []string{"x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0:3.10.0-1160.80.1.0.1.el7",
																			},
																		},
																		Fixed: []string{"0:3.10.0-1160.80.1.0.1.el7"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							ID: "ELSA-2025-20019",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "ELSA-2025-20019",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2025-20019"): {
												{
													Content: advisoryContentTypes.Content{
														ID: "ELSA-2025-20019",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-29901",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2025-20019"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2022-29901",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
																	BaseScore:             5.6,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.6,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.6,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.Oracle: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "kernel-uek",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0:5.4.17-2136.339.5.el7uek",
																			},
																		},
																		Fixed: []string{"0:5.4.17-2136.339.5.el7uek"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-29901": {
					CveID:       "CVE-2022-29901",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-tools",
							NotFixedYet: false,
							FixedIn:     "0:3.10.0-1160.80.1.0.1.el7",
						},
						{
							Name:        "kernel-uek",
							NotFixedYet: false,
							FixedIn:     "0:5.4.17-2136.339.5.el7uek",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "ELSA-2022-7337",
							Issued:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
						{
							AdvisoryID: "ELSA-2025-20019",
							Issued:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Oracle: []models.CveContent{
							{
								Type:          models.Oracle,
								CveID:         "CVE-2022-29901",
								Cvss3Score:    5.6,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://linux.oracle.com/cve/CVE-2022-29901.html",
								References: models.References{
									{
										Link:   "https://linux.oracle.com/errata/ELSA-2022-7337.html",
										Source: "ORACLE",
										RefID:  "ELSA-2022-7337",
									},
									{
										Link:   "https://linux.oracle.com/errata/ELSA-2025-20019.html",
										Source: "ORACLE",
										RefID:  "ELSA-2025-20019",
									},
								},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"ELSA-2022-7337\",\"source_id\":\"oracle\",\"segment\":{\"ecosystem\":\"oracle:7\"}},{\"root_id\":\"ELSA-2025-20019\",\"source_id\":\"oracle\",\"segment\":{\"ecosystem\":\"oracle:7\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: prefer unfixed to fixed",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.18-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "binutils",
							Version: "2.37",
							Release: "7.26.1",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2022-4285",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "SUSE-CU-2023:3179-1",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2022-4285"): {
												{
													Content: advisoryContentTypes.Content{
														ID: "SUSE-CU-2023:3179-1",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-4285",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2022-4285"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2022-4285",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "SUSE",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: true,
																					FixStatus: new(vcFixStatusTypes.FixStatus{
																						Class: vcFixStatusTypes.ClassFixed,
																					}),
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "binutils",
																							Architectures: []string{
																								"aarch64",
																								"ppc64le",
																								"s390x",
																								"x86_64",
																							},
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPM,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								LessThan: "0:2.41-150100.7.46.1",
																							},
																						},
																						Fixed: []string{"0:2.41-150100.7.46.1"},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{0},
																			},
																		},
																	},
																},
															},
														},
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: true,
																					FixStatus: new(vcFixStatusTypes.FixStatus{
																						Class: vcFixStatusTypes.ClassUnfixed,
																					}),
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "binutils",
																							Architectures: []string{
																								"aarch64",
																								"ppc64le",
																								"s390x",
																								"x86_64",
																							},
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPM,
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{0},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-4285": {
					CveID:       "CVE-2022-4285",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "binutils",
							NotFixedYet: true,
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "SUSE-CU-2023:3179-1",
							Issued:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:          models.SUSE,
								CveID:         "CVE-2022-4285",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://www.suse.com/security/cve/CVE-2022-4285.html",
								References: models.References{
									{
										Link:   "https://www.suse.com/security/cve/SUSE-CU-2023:3179-1.html",
										Source: "SUSE",
										RefID:  "SUSE-CU-2023:3179-1",
									},
								},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2022-4285\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 1, in less-than range",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.17",
							Release: "59.37.2",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{0},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-33655": {
					CveID:       "CVE-2021-33655",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-default",
							NotFixedYet: false,
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:         models.SUSE,
								CveID:        "CVE-2021-33655",
								SourceLink:   "https://www.suse.com/security/cve/CVE-2021-33655.html",
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2021-33655\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 2, hit equals",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.18",
							Release: "150300.59.43.1",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{0},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-33655": {
					CveID:       "CVE-2021-33655",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-default",
							NotFixedYet: false,
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:         models.SUSE,
								CveID:        "CVE-2021-33655",
								SourceLink:   "https://www.suse.com/security/cve/CVE-2021-33655.html",
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2021-33655\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 3, livepatch is vulnerable",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.18",
							Release: "150300.59.43.1",
							Arch:    "x86_64",
						},
						{
							Name:    "kernel-livepatch-5_3_18-150300_59_43-default",
							Version: "15",
							Release: "150300.2.2-0",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{2},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{1},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: false,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{0},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-33655": {
					CveID:       "CVE-2021-33655",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-default",
							NotFixedYet: false,
						},
						{
							Name:        "kernel-livepatch-5_3_18-150300_59_43-default",
							NotFixedYet: false,
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:         models.SUSE,
								CveID:        "CVE-2021-33655",
								SourceLink:   "https://www.suse.com/security/cve/CVE-2021-33655.html",
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2021-33655\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 4, not vulnerable by livepatch",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.18",
							Release: "150300.59.43.1",
							Arch:    "x86_64",
						},
						{
							Name:    "kernel-livepatch-5_3_18-150300_59_43-default",
							Version: "16",
							Release: "150300.2.2-0",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{2},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: false,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{0},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			name: "redhat: all vulnerabilities ignored should not fallback to advisory",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "** REJECT ** This CVE has been rejected.",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			name: "debian: advisory without vulnerability",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "libxml2",
							Version:    "2.9.14+dfsg-1.3~deb12u1",
							SrcName:    "libxml2",
							SrcVersion: "2.9.14+dfsg-1.3~deb12u1",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "DSA-5990-1",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "DSA-5990-1",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.DebianSecurityTrackerSalsa: {
											dataTypes.RootID("DSA-5990-1"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "DSA-5990-1",
														Description: "libxml2 security update",
														Published:   new(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("debian:12"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("debian:12"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.DebianSecurityTrackerSalsa: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "libxml2",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "2.9.14+dfsg-1.3~deb12u4",
																			},
																		},
																		Fixed: []string{"2.9.14+dfsg-1.3~deb12u4"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"DSA-5990-1": {
					CveID: "DSA-5990-1",
					Confidences: models.Confidences{
						{
							Score:           100,
							DetectionMethod: "DebianSecurityTrackerMatch",
						},
					},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "libxml2",
							FixedIn:     "2.9.14+dfsg-1.3~deb12u4",
							NotFixedYet: false,
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "DSA-5990-1",
							Description: "libxml2 security update",
							Issued:      time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.DebianSecurityTracker: []models.CveContent{
							{
								Type:       models.DebianSecurityTracker,
								CveID:      "DSA-5990-1",
								Summary:    "libxml2 security update",
								SourceLink: "https://security-tracker.debian.org/tracker/DSA-5990-1",
								References: models.References{
									{
										Link:   "https://security-tracker.debian.org/tracker/DSA-5990-1",
										Source: "DEBIAN",
										RefID:  "DSA-5990-1",
									},
								},
								Published:    time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional:     map[string]string{"vuls2-sources": `[{"root_id":"DSA-5990-1","source_id":"debian-security-tracker-salsa","segment":{"ecosystem":"debian:12"}}]`},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft kb detection: unapplied",
			args: args{
				scanned: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied:   []string{"5025288"},
						Unapplied: []string{"5025221"},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-21234",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-21234",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.MicrosoftCVRF: {
											dataTypes.RootID("CVE-2025-21234"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-21234",
														Title:       "Windows Win32k Elevation of Privilege Vulnerability",
														Description: "A privilege escalation vulnerability.",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
																	BaseScore:    7.8,
																	BaseSeverity: "HIGH",
																}),
															},
														},
														Published: new(time.Date(2025, 5, 13, 0, 0, 0, 0, time.UTC)),
														Optional:  map[string]any{"exploitability": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.MicrosoftCVRF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeKB,
																KB: &kbcriterionTypes.Criterion{
																	Product: "Windows 10 Version 21H2 for x64-based Systems",
																	KBID:    "5025221",
																},
															},
															Accepts: criterionTypes.AcceptQueries{
																KB: criterionTypes.KB{Unapplied: true},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-21234": {
					CveID:       "CVE-2025-21234",
					Confidences: models.Confidences{models.WindowsUpdateSearch},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "KB5025221",
							Description: "Microsoft Knowledge Base",
						},
					},
					WindowsKBFixedIns: []string{"KB5025221"},
					CveContents: models.CveContents{
						models.Microsoft: []models.CveContent{
							{
								Type:          models.Microsoft,
								CveID:         "CVE-2025-21234",
								Title:         "Windows Win32k Elevation of Privilege Vulnerability",
								Summary:       "A privilege escalation vulnerability.",
								Cvss3Score:    7.8,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21234",
								Published:     time.Date(2025, 5, 13, 0, 0, 0, 0, time.UTC),
								LastModified:  time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"exploit":       "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely",
									"vuls2-sources": `[{"root_id":"CVE-2025-21234","source_id":"microsoft-cvrf","segment":{"ecosystem":"microsoft"}}]`,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft kb detection: covered",
			args: args{
				scanned: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied:   []string{"5025221"},
						Unapplied: []string{},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-21235",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-21235",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.MicrosoftCVRF: {
											dataTypes.RootID("CVE-2025-21235"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-21235",
														Title:       "Windows Kernel Information Disclosure Vulnerability",
														Description: "An information disclosure vulnerability.",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
																	BaseScore:    5.5,
																	BaseSeverity: "MEDIUM",
																}),
															},
														},
														Published: new(time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC)),
														Optional:  map[string]any{"exploitability": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.MicrosoftCVRF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeKB,
																KB: &kbcriterionTypes.Criterion{
																	Product: "Windows 10 Version 21H2 for x64-based Systems",
																	KBID:    "5025288",
																},
															},
															Accepts: criterionTypes.AcceptQueries{
																KB: criterionTypes.KB{Covered: true},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-21235": {
					CveID:       "CVE-2025-21235",
					Confidences: models.Confidences{models.WindowsUpdateSearch},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "KB5025288",
							Description: "Microsoft Knowledge Base",
						},
					},
					WindowsKBFixedIns: []string{"KB5025288"},
					CveContents: models.CveContents{
						models.Microsoft: []models.CveContent{
							{
								Type:          models.Microsoft,
								CveID:         "CVE-2025-21235",
								Title:         "Windows Kernel Information Disclosure Vulnerability",
								Summary:       "An information disclosure vulnerability.",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21235",
								Published:     time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
								LastModified:  time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"exploit":       "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely",
									"vuls2-sources": `[{"root_id":"CVE-2025-21235","source_id":"microsoft-cvrf","segment":{"ecosystem":"microsoft"}}]`,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PostConvert(tt.args.scanned, tt.args.detected, tt.args.fsToOriginalCPE)
			if (err != nil) != tt.wantErr {
				t.Errorf("postConvert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff, err := compareVulnInfos(got, tt.want)
			if err != nil {
				t.Errorf("postConvert() compareVulnInfos() error = %v", err)
				return
			}
			if diff != "" {
				t.Errorf("postConvert() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_pruneCriteria(t *testing.T) {
	type args struct {
		ecosystem ecosystemTypes.Ecosystem
		criteria  criteriaTypes.FilteredCriteria
	}
	tests := []struct {
		name    string
		args    args
		want    criteriaTypes.FilteredCriteria
		wantErr bool
	}{
		{
			name: "criterion with accepts, kept as is",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-1",
										},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{
								Version: []int{1},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versioncriterionTypes.Criterion{
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "pkg-1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{
							Version: []int{1},
						},
					},
				},
			},
		},
		{
			name: "criterions without accepts, vanishes in whole",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-1",
										},
									},
								},
							},
						},
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-2",
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{},
			},
		},
		{
			name: "criterions with and without accepts, partially kept",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-1",
										},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{
								Version: []int{1},
							},
						},
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-2",
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versioncriterionTypes.Criterion{
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "pkg-1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{
							Version: []int{1},
						},
					},
				},
			},
		},
		{
			name: "AND-criteria, one criterion has accepts but another does not, vanishes in whole",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-1",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{1},
									},
								},
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-2",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{},
			},
		},
		{
			name: "AND-criterias evaluated to true and false, kept partially",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-1",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{1},
									},
								},
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-2",
												},
											},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-3",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{3},
									},
								},
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-4",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{4},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &versioncriterionTypes.Criterion{
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "pkg-3",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{
									Version: []int{3},
								},
							},
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &versioncriterionTypes.Criterion{
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "pkg-4",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{
									Version: []int{4},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "AND-criterias with true and false criterias in children, kept partially",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-1",
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: []int{1},
											},
										},
									},
								},
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-2",
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: []int{2},
											},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-3",
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: []int{3},
											},
										},
									},
								},
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-4",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &versioncriterionTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "pkg-1",
													},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{
											Version: []int{1},
										},
									},
								},
							},
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &versioncriterionTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "pkg-2",
													},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{
											Version: []int{2},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			// CPE-AND relax: under ecosystem "cpe", vulnerable=false
			// criteria (environment / hardware guards) and subtrees
			// containing only such criteria are skipped before AND
			// evaluation, so the guard cannot veto the vulnerable=true
			// product criterion.
			name: "cpe AND relax: env-only vulnerable=false guard is skipped",
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeCPE,
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeCPE,
										CPE: &cpecriterionTypes.Criterion{
											Vulnerable: false,
											CPE:        cpecriterionTypes.CPE("cpe:2.3:h:vendor:hardware:-:*:*:*:*:*:*:*"),
										},
									},
								},
							},
						},
					},
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeCPE,
								CPE: &cpecriterionTypes.Criterion{
									Vulnerable: true,
									CPE:        cpecriterionTypes.CPE("cpe:2.3:o:vendor:firmware:*:*:*:*:*:*:*:*"),
								},
							},
							Accepts: criterionTypes.AcceptQueries{
								CPE: []int{0},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &cpecriterionTypes.Criterion{
								Vulnerable: true,
								CPE:        cpecriterionTypes.CPE("cpe:2.3:o:vendor:firmware:*:*:*:*:*:*:*:*"),
							},
						},
						Accepts: criterionTypes.AcceptQueries{
							CPE: []int{0},
						},
					},
				},
			},
		},
		{
			// Same shape under a non-CPE ecosystem: no relax, the guard
			// subtree is evaluated normally, comes back empty (its only
			// criterion has no accepts) and fails the whole AND.
			name: "non-cpe ecosystem: vulnerable=false guard still fails the AND",
			args: args{
				ecosystem: ecosystemTypes.Ecosystem("debian:12"),
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeCPE,
										CPE: &cpecriterionTypes.Criterion{
											Vulnerable: false,
											CPE:        cpecriterionTypes.CPE("cpe:2.3:h:vendor:hardware:-:*:*:*:*:*:*:*"),
										},
									},
								},
							},
						},
					},
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeCPE,
								CPE: &cpecriterionTypes.Criterion{
									Vulnerable: true,
									CPE:        cpecriterionTypes.CPE("cpe:2.3:o:vendor:firmware:*:*:*:*:*:*:*:*"),
								},
							},
							Accepts: criterionTypes.AcceptQueries{
								CPE: []int{0},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PruneCriteria(tt.args.ecosystem, tt.args.criteria)
			if (err != nil) != tt.wantErr {
				t.Errorf("pruneCriteria() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := gocmp.Diff(got, tt.want); diff != "" {
				t.Errorf("pruneCriteria() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_enrich(t *testing.T) {
	type args struct {
		vim models.VulnInfos
	}
	tests := []struct {
		name    string
		args    args
		want    models.VulnInfos
		wantErr bool
	}{
		{
			name: "enrich with redhat-cve data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-1102": models.VulnInfo{
						CveID: "CVE-2024-1102",
						CveContents: models.CveContents{
							models.RedHat: []models.CveContent{
								{
									Type:  models.RedHat,
									CveID: "CVE-2024-1102",
									Title: "from-oval",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-1102": models.VulnInfo{
					CveID: "CVE-2024-1102",
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:  models.RedHat,
								CveID: "CVE-2024-1102",
								Title: "from-oval",
							},
						},
						models.RedHatAPI: []models.CveContent{
							{
								Type:          models.RedHatAPI,
								CveID:         "CVE-2024-1102",
								Title:         "jberet: jberet-core logging database credentials",
								Summary:       "A vulnerability was found in jberet-core logging. An exception in 'dbProperties' might display user credentials such as the username and password for the database-connection.\nA vulnerability was found in jberet-core logging. An exception in 'dbProperties' might display user credentials such as the username and password for the database-connection.",
								Cvss3Score:    6.5,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								Cvss3Severity: "Moderate",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2024-1102",
								CweIDs:        []string{"CWE-523"},
								References: models.References{
									{Link: "https://bugzilla.redhat.com/show_bug.cgi?id=2262060", Source: "REDHAT", RefID: "2262060"},
									{Link: "https://github.com/jberet/jsr352/issues/452", Source: "MISC"},
									{Link: "https://nvd.nist.gov/vuln/detail/CVE-2024-1102", Source: "NVD", RefID: "CVE-2024-1102"},
									{Link: "https://www.cve.org/CVERecord?id=CVE-2024-1102", Source: "CVE", RefID: "CVE-2024-1102"},
								},
								Published:    time.Date(2024, 1, 29, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
					Mitigations: []models.Mitigation{
						{
							CveContentType: models.RedHatAPI,
							Mitigation:     "Mitigation for this issue is either not available or the currently available options don't meet the Red Hat Product Security criteria.",
							URL:            "https://access.redhat.com/security/cve/CVE-2024-1102",
						},
					},
				},
			},
		},
		{
			name: "CVE not found in DB leaves VulnInfo unchanged",
			args: args{
				vim: models.VulnInfos{
					"CVE-9999-0001": models.VulnInfo{
						CveID: "CVE-9999-0001",
						CveContents: models.CveContents{
							models.RedHat: []models.CveContent{
								{
									Type:  models.RedHat,
									CveID: "CVE-9999-0001",
									Title: "original",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-9999-0001": models.VulnInfo{
					CveID: "CVE-9999-0001",
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:  models.RedHat,
								CveID: "CVE-9999-0001",
								Title: "original",
							},
						},
					},
				},
			},
		},
		{
			name: "skip if RedHatAPI already present",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-1102": models.VulnInfo{
						CveID: "CVE-2024-1102",
						CveContents: models.CveContents{
							models.RedHatAPI: []models.CveContent{
								{
									Type:  models.RedHatAPI,
									CveID: "CVE-2024-1102",
									Title: "already-enriched",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-1102": models.VulnInfo{
					CveID: "CVE-2024-1102",
					CveContents: models.CveContents{
						models.RedHatAPI: []models.CveContent{
							{
								Type:  models.RedHatAPI,
								CveID: "CVE-2024-1102",
								Title: "already-enriched",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with cisa-kev data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2022-21971": models.VulnInfo{
						CveID:       "CVE-2022-21971",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-21971": models.VulnInfo{
					CveID:       "CVE-2022-21971",
					CveContents: models.CveContents{},
					KEVs: []models.KEV{
						{
							Type:                       models.CISAKEVType,
							VendorProject:              "Microsoft",
							Product:                    "Windows",
							VulnerabilityName:          "Microsoft Windows Runtime Remote Code Execution Vulnerability",
							ShortDescription:           "Microsoft Windows Runtime contains an unspecified vulnerability which allows for remote code execution.",
							RequiredAction:             "Apply updates per vendor instructions.",
							KnownRansomwareCampaignUse: "Unknown",
							DateAdded:                  time.Date(2022, time.August, 18, 0, 0, 0, 0, time.UTC),
							DueDate:                    new(time.Date(2022, time.September, 8, 0, 0, 0, 0, time.UTC)),
							CISA: &models.CISAKEV{
								Note: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21971",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with vulncheck-kev data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2021-30713": models.VulnInfo{
						CveID:       "CVE-2021-30713",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-30713": models.VulnInfo{
					CveID:       "CVE-2021-30713",
					CveContents: models.CveContents{},
					KEVs: []models.KEV{
						{
							Type:                       models.VulnCheckKEVType,
							VendorProject:              "Apple",
							Product:                    "MacOS X",
							VulnerabilityName:          "Apple macOS Unspecified Vulnerability",
							ShortDescription:           "Apple macOS Transparency, Consent, and Control (TCC) contains an unspecified permissions issue which may allow a malicious application to bypass privacy preferences.",
							RequiredAction:             "Apply updates per vendor instructions.",
							KnownRansomwareCampaignUse: "Unknown",
							DateAdded:                  time.Date(2021, time.November, 3, 0, 0, 0, 0, time.UTC),
							DueDate:                    new(time.Date(2021, time.November, 17, 0, 0, 0, 0, time.UTC)),
							VulnCheck: &models.VulnCheckKEV{
								XDB: []models.VulnCheckXDB{
									{
										XDBID:       "a1b2c3",
										XDBURL:      "https://vulncheck.com/xdb/a1b2c3",
										DateAdded:   time.Date(2022, time.March, 15, 0, 0, 0, 0, time.UTC),
										ExploitType: "initial_access",
										CloneSSHURL: "git@github.com:example/exploit.git",
									},
								},
								ReportedExploitation: []models.VulnCheckReportedExploitation{
									{
										URL:       "https://support.apple.com/kb/HT212529",
										DateAdded: time.Date(2022, time.January, 19, 0, 0, 0, 0, time.UTC),
									},
									{
										URL:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
										DateAdded: time.Date(2021, time.November, 3, 0, 0, 0, 0, time.UTC),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with enisa-kev data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-9380": models.VulnInfo{
						CveID:       "CVE-2024-9380",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-9380": models.VulnInfo{
					CveID:       "CVE-2024-9380",
					CveContents: models.CveContents{},
					KEVs: []models.KEV{
						{
							Type:          models.ENISAKEVType,
							VendorProject: "Ivanti",
							Product:       "CSA (Cloud Services Appliance)",
							ENISA: &models.ENISAKEV{
								DateReported: time.Date(2025, time.January, 17, 0, 0, 0, 0, time.UTC),
								PatchedSince: "tbc",
								OriginSource: "cnw",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with metasploit data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-0012": models.VulnInfo{
						CveID:       "CVE-2024-0012",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-0012": models.VulnInfo{
					CveID:       "CVE-2024-0012",
					CveContents: models.CveContents{},
					Metasploits: []models.Metasploit{
						{
							Name:        "exploit/linux/http/panos_management_unauth_rce",
							Title:       "Palo Alto Networks PAN-OS Management Interface Unauthenticated Remote Code Execution",
							Description: "This module exploits an authentication bypass vulnerability (CVE-2024-0012).",
							URLs: []string{
								"https://security.paloaltonetworks.com/CVE-2024-0012",
								"https://www.cve.org/CVERecord?id=CVE-2024-0012",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-exploitdb data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-3132": models.VulnInfo{
						CveID:       "CVE-2017-3132",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-3132": models.VulnInfo{
					CveID:       "CVE-2017-3132",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeExploitDB,
							ID:          "42388",
							URL:         "https://www.exploit-db.com/exploits/42388",
							Description: "Fortinet FortiOS < 5.6.0 - Cross-Site Scripting",
							Verified:    new(true),
							DocumentURL: new("https://www.exploit-db.com/raw/42388"),
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-github data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-9779": models.VulnInfo{
						CveID:       "CVE-2017-9779",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-9779": models.VulnInfo{
					CveID:       "CVE-2017-9779",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeGitHub,
							URL:         "https://github.com/homjxi0e/CVE-2017-9779",
							Description: "Automatic execution Payload From Windows By Path Users All Exploit Via File bashrc ",
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-inthewild data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-16885": models.VulnInfo{
						CveID:       "CVE-2017-16885",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-16885": models.VulnInfo{
					CveID:       "CVE-2017-16885",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeInTheWild,
							URL:         "https://www.exploit-db.com/exploits/43460/",
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-trickest data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-7273": models.VulnInfo{
						CveID:       "CVE-2017-7273",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-7273": models.VulnInfo{
					CveID:       "CVE-2017-7273",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeTrickest,
							URL:         "https://github.com/thdusdl1219/CVE-Study",
							Description: "The cp_report_fixup function in drivers/hid/hid-cypress.c in the Linux kernel 3.2 and 4.x before 4.9.4 allows physically proximate attackers to cause a denial of service (integer underflow) or possibly have unspecified other impact via a crafted HID report.",
						},
						{
							ExploitType: models.ExploitTypeTrickest,
							URL:         "https://github.com/vincent-deng/veracode-container-security-finding-parser",
							Description: "The cp_report_fixup function in drivers/hid/hid-cypress.c in the Linux kernel 3.2 and 4.x before 4.9.4 allows physically proximate attackers to cause a denial of service (integer underflow) or possibly have unspecified other impact via a crafted HID report.",
						},
					},
				},
			},
		},
		{
			name: "enrich with nuclei-repository data (verified=true)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-18565": models.VulnInfo{
						CveID:       "CVE-2017-18565",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-18565": models.VulnInfo{
					CveID:       "CVE-2017-18565",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeNuclei,
							URL:         "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-18565.yaml",
							Description: "The updater plugin before 1.35 for WordPress has multiple XSS issues.",
							Verified:    new(true),
						},
					},
				},
			},
		},
		{
			name: "enrich with nuclei-repository data (verified=false)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-14535": models.VulnInfo{
						CveID:       "CVE-2017-14535",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-14535": models.VulnInfo{
					CveID:       "CVE-2017-14535",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeNuclei,
							URL:         "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14535.yaml",
							Description: "Trixbox 2.8.0.4 is vulnerable to OS command injection via shell metacharacters in the lang parameter to /maint/modules/home/index.php.",
							Verified:    new(false),
						},
					},
				},
			},
		},
		{
			name: "empty VulnInfos",
			args: args{
				vim: models.VulnInfos{},
			},
			want: models.VulnInfos{},
		},
		{
			name: "datasource not in enrich filter is filtered out",
			args: args{
				vim: models.VulnInfos{
					"CVE-2023-44487": models.VulnInfo{
						CveID: "CVE-2023-44487",
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2023-44487": models.VulnInfo{
					CveID:       "CVE-2023-44487",
					CveContents: models.CveContents{},
				},
			},
		},
	}

	c := session.Config{Type: "boltdb", Path: filepath.Join(t.TempDir(), "enrich-test.db")}
	if err := testutil.PopulateDB(c, "testdata/fixtures/enrich"); err != nil {
		t.Fatalf("PopulateDB() err: %v", err)
	}

	sesh, err := c.New()
	if err != nil {
		t.Fatalf("session.Config.New() err: %v", err)
	}
	if err := sesh.Storage().Open(); err != nil {
		t.Fatalf("Storage().Open() err: %v", err)
	}
	defer sesh.Storage().Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := vuls2.Enrich(sesh, tt.args.vim); (err != nil) != tt.wantErr {
				t.Errorf("enrich() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff, err := compareVulnInfos(tt.args.vim, tt.want)
			if err != nil {
				t.Errorf("enrich() compareVulnInfos() error = %v", err)
			}
			if diff != "" {
				t.Errorf("enrich() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func compareVulnInfos(a, b models.VulnInfos) (string, error) {
	ks := make(map[string]struct{})
	for k := range a {
		ks[k] = struct{}{}
	}
	for k := range b {
		ks[k] = struct{}{}
	}

	var sb strings.Builder
	for k := range ks {
		if diff := gocmp.Diff(a[k], b[k], []gocmp.Option{
			gocmpopts.SortSlices(func(a, b models.Confidence) bool {
				return cmp.Compare(a.DetectionMethod, b.DetectionMethod) < 0
			}),
			gocmpopts.SortSlices(func(a, b models.DistroAdvisory) bool {
				return cmp.Or(
					cmp.Compare(a.AdvisoryID, b.AdvisoryID),
					cmp.Compare(a.Severity, b.Severity),
					a.Issued.Compare(b.Issued),
					a.Updated.Compare(b.Updated),
				) < 0
			}),
			gocmpopts.SortSlices(func(a, b models.PackageFixStatus) bool {
				return cmp.Or(
					cmp.Compare(a.Name, b.Name),
					cmp.Compare(a.FixState, b.FixState),
					cmp.Compare(a.FixedIn, b.FixedIn),
				) < 0
			}),
			gocmpopts.SortSlices(func(a, b models.Reference) bool {
				return cmp.Compare(a.Link, b.Link) < 0
			}),
		}...); diff != "" {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, diff))
		}
	}

	return sb.String(), nil
}
