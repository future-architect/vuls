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
	versoncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
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
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/models"
)

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
							Epoch:   toPtr(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   toPtr(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package3",
							Epoch:   toPtr(0),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Vendor: toPtr("CRITICAL"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: toPtr(cvssV40Types.CVSSv40{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																CVSSv2: toPtr(cvssV2Types.CVSSv2{
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
																CVSSv30: toPtr(cvssV30Types.CVSSv30{
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
																CVSSv40: toPtr(cvssV40Types.CVSSv40{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
							Epoch:   toPtr(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   toPtr(0),
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
																Vendor: toPtr("MEDIUM"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Vendor: toPtr("HIGH"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Vendor: toPtr("CRITICAL"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Vendor: toPtr("CRITICAL"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Vendor: toPtr("HIGH"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Vendor: toPtr("MEDIUM"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Vendor: toPtr("HIGH"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv40: toPtr(cvssV40Types.CVSSv40{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEX: {
											dataTypes.RootID("CVE-2025-0003"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "[REJECTED CVE] description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
							Epoch:   toPtr(0),
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
																Vendor: toPtr("CRITICAL"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
							Epoch:   toPtr(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   toPtr(0),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeCPE,
																		CPE:  toPtr(vcCPEPackageTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*")),
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
																Vendor: toPtr("MEDIUM"),
															},
														},
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
							Epoch:   toPtr(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "kpatch-patch-1",
							Epoch:   toPtr(0),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																		NoneExist: toPtr(noneexistcriterionTypes.Criterion{
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
																		Version: toPtr(versoncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																		Version: toPtr(versoncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																		Version: toPtr(versoncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																CVSSv31: toPtr(cvssV31Types.CVSSv31{
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
							Epoch:   toPtr(0),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
							Epoch:   toPtr(0),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published:   toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
														Published: toPtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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
																Version: toPtr(versoncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: toPtr(vcFixStatusTypes.FixStatus{
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

func toPtr[T any](x T) *T {
	return &x
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
