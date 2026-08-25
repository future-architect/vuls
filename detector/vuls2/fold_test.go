package vuls2_test

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

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
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"

	vuls2 "github.com/future-architect/vuls/detector/vuls2"
)

func Test_projectCPECriteria(t *testing.T) {
	cpeCriterion := func(vulnerable bool, cpe string, exact, vp []int, matches ...string) criterionTypes.FilteredCriterion {
		c := ccTypes.Criterion{Vulnerable: vulnerable, CPE: ccTypes.CPE(cpe)}
		if vulnerable {
			c.Range = &ccRangeTypes.Range{}
		}
		for _, m := range matches {
			c.CPEMatches = append(c.CPEMatches, ccTypes.CPE(m))
		}
		return criterionTypes.FilteredCriterion{
			Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &c},
			Accepts:   criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: exact, VersionUnconfirmed: vp}},
		}
	}
	// a kept (walk-ready) criterion: vulnerable, product-form CPE, Accepts intact
	keptCriterion := func(cpe string, exact, vp []int, matches ...string) criterionTypes.FilteredCriterion {
		c := ccTypes.Criterion{Vulnerable: true, CPE: ccTypes.CPE(cpe)}
		for _, m := range matches {
			c.CPEMatches = append(c.CPEMatches, ccTypes.CPE(m))
		}
		return criterionTypes.FilteredCriterion{
			Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &c},
			Accepts:   criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: exact, VersionUnconfirmed: vp}},
		}
	}

	tests := []struct {
		name         string
		ca           criteriaTypes.FilteredCriteria
		wantCriteria criteriaTypes.FilteredCriteria
		wantDefined  []string
	}{
		{
			name:         "empty",
			ca:           criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
			wantCriteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
			wantDefined:  nil,
		},
		{
			// The kept criterion's CPE and CPEMatches are reduced to
			// part:vendor:product form; matches sharing the criterion's own
			// product are deduplicated away.
			name: "flat OR, one exact accept",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(true, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", []int{0}, nil,
						"cpe:2.3:o:linux:linux_kernel:5.10.1:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:5.10.2:*:*:*:*:*:*:*"),
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					keptCriterion("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", []int{0}, nil),
				},
			},
			wantDefined: []string{"o:linux:linux_kernel"},
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
						cpeCriterion(true, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", nil, []int{0}),
						cpeCriterion(false, "cpe:2.3:h:vendorx:boardx:-:*:*:*:*:*:*:*", nil, nil,
							"cpe:2.3:h:vendorx:boardy:-:*:*:*:*:*:*:*"),
					},
				}},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					keptCriterion("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", nil, []int{0}),
				},
			},
			wantDefined: []string{"h:vendorx:boardx", "h:vendorx:boardy", "o:linux:linux_kernel"},
		},
		{
			// A vulnerable criterion that accepted nothing is dropped from the
			// walk-ready tree but keeps contributing defined products.
			name: "unaccepted vulnerable criterion contributes defined products only",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(true, "cpe:2.3:a:vendorc:productc:*:*:*:*:*:*:*:*", nil, nil,
						"cpe:2.3:a:vendorc:productc:1.2.3:*:*:*:*:*:*:*"),
					cpeCriterion(true, "cpe:2.3:a:vendorb:productb:*:*:*:*:*:*:*:*", []int{1}, nil),
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					keptCriterion("cpe:2.3:a:vendorb:productb:*:*:*:*:*:*:*:*", []int{1}, nil),
				},
			},
			wantDefined: []string{"a:vendorb:productb", "a:vendorc:productc"},
		},
		{
			name: "nested OR under AND, both tiers accepted",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
				Criterias: []criteriaTypes.FilteredCriteria{{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion(true, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", []int{0}, []int{1}),
					},
				}},
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(false, "cpe:2.3:h:vendorx:boardx:-:*:*:*:*:*:*:*", nil, nil),
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					keptCriterion("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", []int{0}, []int{1}),
				},
			},
			wantDefined: []string{"h:vendorx:boardx", "o:linux:linux_kernel"},
		},
		{
			// An unparsable CPE cannot be product-reduced: the kept criterion
			// carries it verbatim, unparsable matches are dropped, and no
			// defined product is recorded.
			name: "invalid CPE strings are tolerated",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(true, "not-a-cpe", []int{0}, nil, "also-not-a-cpe"),
					cpeCriterion(false, "not-a-cpe-either", nil, nil),
				},
			},
			wantCriteria: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					keptCriterion("not-a-cpe", []int{0}, nil),
				},
			},
			wantDefined: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCriteria, gotDefined := vuls2.ProjectCPECriteria(tt.ca)
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
		name string
		d    detectTypes.VulnerabilityDataDetection
		want vuls2.Detection
	}{
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
			want: vuls2.Detection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]vuls2.Condition{
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
			want: vuls2.Detection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]vuls2.Condition{
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
			want: vuls2.Detection{
				Ecosystem: ecosystem,
				Contents: map[sourceTypes.SourceID][]vuls2.Condition{
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
			want: vuls2.Detection{
				Ecosystem: ecosystem,
				Contents:  map[sourceTypes.SourceID][]vuls2.Condition{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.ProjectOSPkgDetection(tt.d)
			if err != nil {
				t.Fatalf("projectOSPkgDetection. error = %v", err)
			}
			if diff := gocmp.Diff(tt.want, got, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("projectOSPkgDetection() (-expected +got):\n%s", diff)
			}
		})
	}
}
