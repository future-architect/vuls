package vuls2_test

import (
	"cmp"
	"fmt"
	"strings"
	"testing"
	"time"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	versioncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	vcCPEPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	cvssV40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/models"
)

func Test_preConvert(t *testing.T) {
	type args struct {
		sr *models.ScanResult
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := gocmp.Diff(vuls2.PreConvert(tt.args.sr), tt.want, gocmpopts.IgnoreFields(scanTypes.ScanResult{}, "ScannedAt", "ScannedBy")); diff != "" {
				t.Errorf("preConvert() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_postConvert(t *testing.T) {
	type args struct {
		scanned  scanTypes.ScanResult
		detected detectTypes.DetectResult
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEX: {
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
										sourceTypes.Fedora: {
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
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEX: {
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
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeCPE,
																		CPE:  new(vcCPEPackageTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*")),
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
							ID: "FEDORA-EPEL-2025-0123456789",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FEDORA-EPEL-2025-0123456789",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.Fedora: {
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.Fedora: {
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
										sourceTypes.Fedora: {
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
										sourceTypes.Fedora: {
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
					CpeURIs: []string{"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
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
									"vuls2-sources": "[{\"root_id\":\"FEDORA-EPEL-2025-0123456789\",\"source_id\":\"fedora\",\"segment\":{\"ecosystem\":\"epel:9\"}}]",
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
									"vuls2-sources": "[{\"root_id\":\"FEDORA-EPEL-2025-0123456789\",\"source_id\":\"fedora\",\"segment\":{\"ecosystem\":\"epel:9\"}}]",
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
										sourceTypes.RedHatVEX: {
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
										sourceTypes.RedHatVEX: {
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
																				Version: toPtr(versioncriterionTypes.Criterion{
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
																				Version: toPtr(versioncriterionTypes.Criterion{
																					Vulnerable: true,
																					FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																				Version: toPtr(versioncriterionTypes.Criterion{
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
																				Version: toPtr(versioncriterionTypes.Criterion{
																					Vulnerable: true,
																					FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																				Version: toPtr(versioncriterionTypes.Criterion{
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																						Version: toPtr(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassUnknown,
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
							NotFixedYet: true,
							FixState:    "Unknown",
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
																				Version: toPtr(versioncriterionTypes.Criterion{
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																						Version: toPtr(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassUnknown,
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
							NotFixedYet: true,
							FixState:    "Unknown",
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
																				Version: toPtr(versioncriterionTypes.Criterion{
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																						Version: toPtr(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassUnknown,
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
							NotFixedYet: true,
							FixState:    "Unknown",
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
																				Version: toPtr(versioncriterionTypes.Criterion{
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																										Version: toPtr(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																										NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																								Version: toPtr(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassUnknown,
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
																						Version: toPtr(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassUnknown,
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PostConvert(tt.args.scanned, tt.args.detected)
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
		criteria criteriaTypes.FilteredCriteria
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PruneCriteria(tt.args.criteria)
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
