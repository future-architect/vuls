package vuls2_test

import (
	"errors"
	"fmt"
	"iter"
	"runtime"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	versioncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"

	vuls2 "github.com/future-architect/vuls/detector/vuls2"
)

func Test_projectCPECriteria(t *testing.T) {
	tests := []struct {
		name         string
		ca           criteriaTypes.FilteredCriteria
		wantCriteria criteriaTypes.FilteredCriteria
		wantDefined  map[string]struct{}
		wantErr      bool
	}{
		{
			name:         "empty",
			ca:           criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
			wantCriteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
			wantDefined:  nil,
		},
		{
			// The kept criterion carries its CPE string verbatim; CPEMatches
			// and Range are dropped (the walk reads none of them).
			name: "flat OR, one exact accept",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								Vulnerable: true,
								CPE:        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
								Range:      &ccRangeTypes.Range{},
								CPEMatches: []ccTypes.CPE{
									"cpe:2.3:o:linux:linux_kernel:5.10.1:*:*:*:*:*:*:*",
									"cpe:2.3:o:linux:linux_kernel:5.10.2:*:*:*:*:*:*:*",
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
					},
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
					},
				},
			},
			wantDefined: map[string]struct{}{"o:linux:linux_kernel": {}},
		},
		{
			// The non-vulnerable hardware guard is dropped from the walk-ready
			// tree but its products (own CPE and CPEMatches) stay defined; the
			// accepted criterion is flattened out of the AND child.
			name: "AND with non-vulnerable hardware guard defining extra products",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeCPE,
								CPE: &ccTypes.Criterion{
									Vulnerable: true,
									CPE:        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
									Range:      &ccRangeTypes.Range{},
								},
							},
							Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{VersionUnconfirmed: []int{0}}},
						},
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeCPE,
								CPE: &ccTypes.Criterion{
									Vulnerable: false,
									CPE:        "cpe:2.3:h:vendorx:boardx:-:*:*:*:*:*:*:*",
									CPEMatches: []ccTypes.CPE{"cpe:2.3:h:vendorx:boardy:-:*:*:*:*:*:*:*"},
								},
							},
						},
					},
				}},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{VersionUnconfirmed: []int{0}}},
					},
				},
			},
			wantDefined: map[string]struct{}{"h:vendorx:boardx": {}, "h:vendorx:boardy": {}, "o:linux:linux_kernel": {}},
		},
		{
			// A vulnerable criterion that accepted nothing is dropped from the
			// walk-ready tree but keeps contributing defined products.
			name: "unaccepted vulnerable criterion contributes defined products only",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								Vulnerable: true,
								CPE:        "cpe:2.3:a:vendorc:productc:*:*:*:*:*:*:*:*",
								Range:      &ccRangeTypes.Range{},
								CPEMatches: []ccTypes.CPE{"cpe:2.3:a:vendorc:productc:1.2.3:*:*:*:*:*:*:*"},
							},
						},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								Vulnerable: true,
								CPE:        "cpe:2.3:a:vendorb:productb:*:*:*:*:*:*:*:*",
								Range:      &ccRangeTypes.Range{},
							},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{1}}},
					},
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "cpe:2.3:a:vendorb:productb:*:*:*:*:*:*:*:*"},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{1}}},
					},
				},
			},
			wantDefined: map[string]struct{}{"a:vendorb:productb": {}, "a:vendorc:productc": {}},
		},
		{
			name: "nested OR under AND, both tiers accepted",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeCPE,
								CPE: &ccTypes.Criterion{
									Vulnerable: true,
									CPE:        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
									Range:      &ccRangeTypes.Range{},
								},
							},
							Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}, VersionUnconfirmed: []int{1}}},
						},
					},
				}},
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								Vulnerable: false,
								CPE:        "cpe:2.3:h:vendorx:boardx:-:*:*:*:*:*:*:*",
							},
						},
					},
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}, VersionUnconfirmed: []int{1}}},
					},
				},
			},
			wantDefined: map[string]struct{}{"h:vendorx:boardx": {}, "o:linux:linux_kernel": {}},
		},
		{
			// An unparsable CPE records no defined product but is still
			// carried on the kept criterion.
			name: "invalid CPE strings are tolerated",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								Vulnerable: true,
								CPE:        "not-a-cpe",
								Range:      &ccRangeTypes.Range{},
								CPEMatches: []ccTypes.CPE{"also-not-a-cpe"},
							},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE: &ccTypes.Criterion{
								Vulnerable: false,
								CPE:        "not-a-cpe-either",
							},
						},
					},
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeCPE,
							CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "not-a-cpe"},
						},
						Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
					},
				},
			},
			wantDefined: nil,
		},
		{
			name:    "unexpected operator fails fast",
			ca:      criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorType("future-operator")},
			wantErr: true,
		},
		{
			name: "unexpected operator in a child fails fast",
			ca: criteriaTypes.FilteredCriteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{{Operator: criteriaTypes.CriteriaOperatorType("future-operator")}},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCriteria, gotDefined, err := vuls2.ProjectCPECriteria(tt.ca, true)
			if (err != nil) != tt.wantErr {
				t.Fatalf("projectCPECriteria() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := gocmp.Diff(tt.wantCriteria, gotCriteria, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("projectCPECriteria() criteria (-expected +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantDefined, gotDefined, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("projectCPECriteria() defined products (-expected +got):\n%s", diff)
			}
		})
	}
}

// Test_projectOSPkgDetection: prunePkgCriteria's gate semantics are
// covered by Test_prunePkgCriteria; here the wrapper's own behavior is
// pinned — every condition's tree is gate-pruned, conditions whose tree
// prunes to empty are dropped, and sources with no remaining conditions
// are removed.
func Test_projectOSPkgDetection(t *testing.T) {
	ecosystem := ecosystemTypes.Ecosystem("redhat:8")

	vc := func(name string, accepts []int) criterionTypes.FilteredCriterion {
		return criterionTypes.FilteredCriterion{
			Criterion: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
				Version: &versioncriterionTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
					Package: vcPackageTypes.Package{
						Type:   vcPackageTypes.PackageTypeBinary,
						Binary: &vcBinaryPackageTypes.Package{Name: name, Architectures: []string{"x86_64"}},
					},
					Affected: &vcAffectedTypes.Affected{Type: vcAffectedRangeTypes.RangeTypeRPM, Fixed: []string{"0:9.9.9-1"}},
				},
			},
			Accepts: criterionTypes.AcceptQueries{Version: accepts},
		}
	}

	tests := []struct {
		name    string
		d       detectTypes.VulnerabilityDataDetection
		want    vuls2.ProjectedDetection
		wantErr bool
	}{
		{
			// The projector is picked per Detect stream while the walker
			// dispatches on Ecosystem; a cpe detection reaching the ospkg
			// projector is the mismatch the assertion pins.
			name: "cpe detection is rejected",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
			},
			wantErr: true,
		},
		{
			name: "OR keeps accepted, drops unaccepted",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{vc("kernel", []int{0}), vc("kernel-debug", nil)},
						},
					}},
				},
			},
			want: vuls2.ProjectedDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]vuls2.ProjectedCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{vc("kernel", []int{0})},
						},
					}},
				},
			},
		},
		{
			name: "AND with unaccepted child drops the whole condition and source",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{{
								Operator:   criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{vc("kpatch-patch", nil)},
							}},
							Criterions: []criterionTypes.FilteredCriterion{vc("kernel", []int{0})},
						},
					}},
					sourceTypes.RedHatCSAF: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{vc("openssl", []int{1})},
						},
					}},
				},
			},
			want: vuls2.ProjectedDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]vuls2.ProjectedCondition{
					sourceTypes.RedHatCSAF: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{vc("openssl", []int{1})},
						},
					}},
				},
			},
		},
		{
			name: "nested OR under AND survives when all gates pass",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{{
								Operator:   criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{vc("kernel", []int{0}), vc("kernel-rt", nil)},
							}},
						},
					}},
				},
			},
			want: vuls2.ProjectedDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]vuls2.ProjectedCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{{
								Operator:   criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{vc("kernel", []int{0})},
							}},
						},
					}},
				},
			},
		},
		{
			name: "every source dropping empties Contents",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{vc("kernel-debug", nil)},
						},
					}},
				},
			},
			want: vuls2.ProjectedDetection{
				Ecosystem: ecosystem,
				Contents:  map[sourceTypes.SourceID][]vuls2.ProjectedCondition{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.ProjectOSPkgDetection(tt.d)
			if (err != nil) != tt.wantErr {
				t.Fatalf("projectOSPkgDetection() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := gocmp.Diff(tt.want, got, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("projectOSPkgDetection() (-expected +got):\n%s", diff)
			}
		})
	}
}

// Test_projectCPEDetection: projectCPECriteria's projection semantics are
// covered by Test_projectCPECriteria; here the wrapper's own behavior is
// pinned — the asymmetry with projectOSPkgDetection (no condition or
// source is dropped, even when the walk-ready tree is empty) and the
// DefinedProducts gate (collected per condition for verifiedCPESources,
// nil for every other source, mirroring collectVerifiedProducts' read).
func Test_projectCPEDetection(t *testing.T) {
	tests := []struct {
		name    string
		d       detectTypes.VulnerabilityDataDetection
		want    vuls2.ProjectedDetection
		wantErr bool
	}{
		{
			// Contrast with projectOSPkgDetection: the second condition's
			// walk-ready tree is empty (no accepted criterion) but the
			// condition survives with its DefinedProducts, and so does its
			// source key.
			name: "no condition or source dropped; DefinedProducts per condition for a verified source",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.NVDFeedCVEv2: {
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeCPE,
											CPE: &ccTypes.Criterion{
												Vulnerable: true,
												CPE:        "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*",
												Range:      &ccRangeTypes.Range{},
												CPEMatches: []ccTypes.CPE{"cpe:2.3:o:xen:xen:-:*:*:*:*:*:*:*"},
											},
										},
										Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
									},
								},
							},
							Tag: segmentTypes.DetectionTag("t1"),
						},
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeCPE,
											CPE: &ccTypes.Criterion{
												Vulnerable: true,
												CPE:        "cpe:2.3:a:vendora:producta:1.0:*:*:*:*:*:*:*",
												Range:      &ccRangeTypes.Range{},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: vuls2.ProjectedDetection{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Contents: map[sourceTypes.SourceID][]vuls2.ProjectedCondition{
					sourceTypes.NVDFeedCVEv2: {
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeCPE,
											CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*"},
										},
										Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
									},
								},
							},
							Tag:             segmentTypes.DetectionTag("t1"),
							DefinedProducts: map[string]struct{}{"o:linux:linux_kernel": {}, "o:xen:xen": {}},
						},
						{
							Criteria:        criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
							DefinedProducts: map[string]struct{}{"a:vendora:producta": {}},
						},
					},
				},
			},
		},
		{
			// collectVerifiedProducts only reads DefinedProducts for
			// verifiedCPESources; for every other source the projection
			// skips the UnbindFS work and carries nil.
			name: "DefinedProducts collection is gated to verified sources",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.VulnCheckNISTNVD2: {
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeCPE,
											CPE: &ccTypes.Criterion{
												Vulnerable: true,
												CPE:        "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*",
												Range:      &ccRangeTypes.Range{},
												CPEMatches: []ccTypes.CPE{"cpe:2.3:o:xen:xen:-:*:*:*:*:*:*:*"},
											},
										},
										Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
									},
								},
							},
						},
					},
				},
			},
			want: vuls2.ProjectedDetection{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Contents: map[sourceTypes.SourceID][]vuls2.ProjectedCondition{
					sourceTypes.VulnCheckNISTNVD2: {
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeCPE,
											CPE:  &ccTypes.Criterion{Vulnerable: true, CPE: "cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*"},
										},
										Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "unexpected operator propagates as an error",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.NVDFeedCVEv2: {{Criteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorType("future-operator")}}},
				},
			},
			wantErr: true,
		},
		{
			// Mirror of Test_projectOSPkgDetection's "cpe detection is
			// rejected": an ospkg detection reaching the cpe projector.
			name: "non-cpe detection is rejected",
			d: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystemTypes.Ecosystem("redhat:8"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.ProjectCPEDetection(tt.d)
			if (err != nil) != tt.wantErr {
				t.Fatalf("projectCPEDetection() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := gocmp.Diff(tt.want, got, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("projectCPEDetection() (-expected +got):\n%s", diff)
			}
		})
	}
}

func Test_foldDetectionSeq(t *testing.T) {
	warned := func(rootID string) detectTypes.RootDetection {
		return detectTypes.RootDetection{
			RootID: dataTypes.RootID(rootID),
			Detection: detectTypes.VulnerabilityDataDetection{
				Ecosystem: ecosystemTypes.Ecosystem("redhat:8"),
				Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
					sourceTypes.RedHatOVALv2: {{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{{
								Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
								Warnings:  []warningTypes.Warning{{Kind: warningTypes.KindEmptyRange}},
							}},
						},
					}},
				},
			},
		}
	}
	seqOf := func(rds []detectTypes.RootDetection, terminalErr error) iter.Seq2[detectTypes.RootDetection, error] {
		return func(yield func(detectTypes.RootDetection, error) bool) {
			for _, rd := range rds {
				if !yield(rd, nil) {
					return
				}
			}
			if terminalErr != nil {
				yield(detectTypes.RootDetection{}, terminalErr)
			}
		}
	}
	// mark projects a detection to a recognizable empty ProjectedDetection,
	// dropping the tree (and the warnings riding on it).
	mark := func(d detectTypes.VulnerabilityDataDetection) (vuls2.ProjectedDetection, bool, error) {
		return vuls2.ProjectedDetection{Ecosystem: d.Ecosystem}, true, nil
	}

	t.Run("accumulates projections and harvests warnings before them", func(t *testing.T) {
		m, warnings, err := vuls2.FoldDetectionSeq(seqOf([]detectTypes.RootDetection{warned("ROOT-1"), warned("ROOT-2")}, nil), mark)
		if err != nil {
			t.Fatalf("foldDetectionSeq. error = %v", err)
		}
		want := map[dataTypes.RootID]vuls2.ProjectedDetection{
			"ROOT-1": {Ecosystem: ecosystemTypes.Ecosystem("redhat:8")},
			"ROOT-2": {Ecosystem: ecosystemTypes.Ecosystem("redhat:8")},
		}
		if diff := gocmp.Diff(want, m, gocmpopts.EquateEmpty()); diff != "" {
			t.Errorf("result (-expected +got):\n%s", diff)
		}
		// The projection dropped the trees, so the warning can only have been
		// harvested from the full tree beforehand (deduplicated across roots).
		wantWarnings := []vuls2.WarningEntry{{Source: sourceTypes.RedHatOVALv2, Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}}}
		if diff := gocmp.Diff(wantWarnings, warnings); diff != "" {
			t.Errorf("warnings (-expected +got):\n%s", diff)
		}
	})

	t.Run("keep=false drops the rootID but keeps its warnings", func(t *testing.T) {
		m, warnings, err := vuls2.FoldDetectionSeq(seqOf([]detectTypes.RootDetection{warned("ROOT-1")}, nil), func(_ detectTypes.VulnerabilityDataDetection) (vuls2.ProjectedDetection, bool, error) {
			return vuls2.ProjectedDetection{}, false, nil
		})
		if err != nil {
			t.Fatalf("foldDetectionSeq. error = %v", err)
		}
		if len(m) != 0 {
			t.Errorf("expected empty result, got %v", m)
		}
		if len(warnings) != 1 {
			t.Errorf("expected the dropped root's warning to be kept, got %v", warnings)
		}
	})

	t.Run("project error is terminal and carries the rootID", func(t *testing.T) {
		_, _, err := vuls2.FoldDetectionSeq(seqOf([]detectTypes.RootDetection{warned("ROOT-1")}, nil), func(_ detectTypes.VulnerabilityDataDetection) (vuls2.ProjectedDetection, bool, error) {
			return vuls2.ProjectedDetection{}, false, errors.New("boom")
		})
		if err == nil || !strings.Contains(err.Error(), "ROOT-1") || !strings.Contains(err.Error(), "boom") {
			t.Errorf("expected wrapped project error naming the root, got %v", err)
		}
	})

	t.Run("project error stops the stream consumption", func(t *testing.T) {
		// The consumer can schedule up to the fold pool size before the
		// first worker error cancels gctx, so the floor must scale with
		// NumCPU for the assertion to hold on very wide hosts.
		n := max(64, 2*runtime.NumCPU())
		consumed := 0
		seq := func(yield func(detectTypes.RootDetection, error) bool) {
			for i := range n {
				consumed++
				if !yield(warned(fmt.Sprintf("ROOT-%03d", i)), nil) {
					return
				}
			}
		}
		_, _, err := vuls2.FoldDetectionSeq(seq, func(_ detectTypes.VulnerabilityDataDetection) (vuls2.ProjectedDetection, bool, error) {
			return vuls2.ProjectedDetection{}, false, errors.New("boom")
		})
		if err == nil {
			t.Fatal("expected an error")
		}
		// Breaking out of the range is what cancels vuls2's producer, so an
		// early project failure must not drain the whole stream.
		if consumed == n {
			t.Errorf("stream fully consumed (%d elements) despite an early project error", consumed)
		}
	})

	t.Run("stream error is terminal and outranks a project error", func(t *testing.T) {
		streamErr := errors.New("stream broke")
		_, _, err := vuls2.FoldDetectionSeq(seqOf([]detectTypes.RootDetection{warned("ROOT-1")}, streamErr), func(_ detectTypes.VulnerabilityDataDetection) (vuls2.ProjectedDetection, bool, error) {
			return vuls2.ProjectedDetection{}, false, errors.New("worker broke")
		})
		if !errors.Is(err, streamErr) {
			t.Errorf("expected the stream error, got %v", err)
		}
	})
}
