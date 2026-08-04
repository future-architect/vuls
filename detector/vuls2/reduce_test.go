package vuls2_test

import (
	"fmt"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

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
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"

	vuls2 "github.com/future-architect/vuls/detector/vuls2"
)

// TestCompactCPECriteriaInvariants checks the contract compactCPEDetection
// relies on: for every consumer read of a cpe-ecosystem criteria tree —
// walkCPECriteria's projection (per source class) and
// collectDefinedCPEProducts' defined-product set — the compacted tree is
// indistinguishable from the original.
func TestCompactCPECriteriaInvariants(t *testing.T) {
	scanned := scanTypes.ScanResult{CPE: []string{
		"cpe:2.3:o:linux:linux_kernel:5.10.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:vendorb:productb:2.0:*:*:*:*:*:*:*",
	}}

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

	tests := []struct {
		name string
		ca   criteriaTypes.FilteredCriteria
	}{
		{
			name: "empty",
			ca:   criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
		},
		{
			name: "flat OR, one exact accept",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(true, "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", []int{0}, nil,
						"cpe:2.3:o:linux:linux_kernel:5.10.1:*:*:*:*:*:*:*", "cpe:2.3:o:linux:linux_kernel:5.10.2:*:*:*:*:*:*:*"),
				},
			},
		},
		{
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
		},
		{
			name: "unaccepted vulnerable criterion contributes defined products only",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(true, "cpe:2.3:a:vendorc:productc:*:*:*:*:*:*:*:*", nil, nil,
						"cpe:2.3:a:vendorc:productc:1.2.3:*:*:*:*:*:*:*"),
					cpeCriterion(true, "cpe:2.3:a:vendorb:productb:*:*:*:*:*:*:*:*", []int{1}, nil),
				},
			},
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
		},
		{
			name: "invalid CPE strings are tolerated",
			ca: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					cpeCriterion(true, "not-a-cpe", []int{0}, nil, "also-not-a-cpe"),
					cpeCriterion(false, "not-a-cpe-either", nil, nil),
				},
			},
		},
	}

	sources := []sourceTypes.SourceID{
		sourceTypes.NVDAPICVE,         // verified
		sourceTypes.VulnCheckNISTNVD2, // suppressed
		sourceTypes.JVNFeedRSS,        // suppressed + JVN demotion
	}
	verifiedProducts := map[string]struct{}{"o:linux:linux_kernel": {}}
	noJVNCPEs := map[string]struct{}{scanned.CPE[1]: {}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compacted := vuls2.CompactCPECriteria(tt.ca)

			for _, sourceID := range sources {
				for _, vp := range []map[string]struct{}{nil, verifiedProducts} {
					name := fmt.Sprintf("%s/verified=%t", sourceID, vp != nil)
					wantExact, wantVP, wantErr := vuls2.WalkCPECriteria(sourceID, tt.ca, scanned, noJVNCPEs, vp)
					gotExact, gotVP, gotErr := vuls2.WalkCPECriteria(sourceID, compacted, scanned, noJVNCPEs, vp)
					if (wantErr != nil) != (gotErr != nil) {
						t.Errorf("%s: walkCPECriteria error mismatch: original %v, compacted %v", name, wantErr, gotErr)
						continue
					}
					if diff := gocmp.Diff(wantExact, gotExact); diff != "" {
						t.Errorf("%s: exact (-original +compacted):\n%s", name, diff)
					}
					if diff := gocmp.Diff(wantVP, gotVP); diff != "" {
						t.Errorf("%s: vendor-product (-original +compacted):\n%s", name, diff)
					}
				}
			}

			wantSet := make(map[string]struct{})
			vuls2.CollectDefinedCPEProducts(tt.ca, wantSet)
			gotSet := make(map[string]struct{})
			vuls2.CollectDefinedCPEProducts(compacted, gotSet)
			if diff := gocmp.Diff(wantSet, gotSet); diff != "" {
				t.Errorf("collectDefinedCPEProducts (-original +compacted):\n%s", diff)
			}
		})
	}
}

// TestPruneAffectedDetectionInvariants checks the contract the streaming
// ospkg fold relies on: walkPkgCriteria (which itself starts from
// prunePkgCriteria — the same gate, making the early pruning idempotent)
// projects the pruned detection onto identical pack statuses / KB IDs, and
// conditions carrying no detection signal are exactly the ones dropped.
func TestPruneAffectedDetectionInvariants(t *testing.T) {
	scanned := scanTypes.ScanResult{
		Family: ecosystemTypes.EcosystemTypeRedHat,
		OSPackages: []scanTypes.OSPackage{
			{Name: "kernel", Version: "4.18.0", Release: "513.11.1.el8_9", Arch: "x86_64"},
			{Name: "openssl", Version: "1.1.1k", Release: "12.el8_9", Arch: "x86_64"},
		},
	}
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pruned, err := vuls2.PruneAffectedDetection(tt.d)
			if err != nil {
				t.Fatalf("pruneAffectedDetection. error = %v", err)
			}

			for sid, conds := range tt.d.Contents {
				var wantStatuses, gotStatuses [][]any
				for _, cond := range conds {
					ss, ks, err := vuls2.WalkPkgCriteria(tt.d.Ecosystem, sid, cond.Criteria, cond.Tag, scanned)
					if err != nil {
						t.Fatalf("walk original. error = %v", err)
					}
					if len(ss) > 0 || len(ks) > 0 {
						wantStatuses = append(wantStatuses, []any{ss, ks})
					}
				}
				for _, cond := range pruned.Contents[sid] {
					ss, ks, err := vuls2.WalkPkgCriteria(tt.d.Ecosystem, sid, cond.Criteria, cond.Tag, scanned)
					if err != nil {
						t.Fatalf("walk pruned. error = %v", err)
					}
					gotStatuses = append(gotStatuses, []any{ss, ks})
				}
				if diff := gocmp.Diff(wantStatuses, gotStatuses, gocmp.Comparer(func(a, b vuls2.PackStatus) bool { return a == b })); diff != "" {
					t.Errorf("source %s: walkPkgCriteria (-original +pruned):\n%s", sid, diff)
				}
			}
		})
	}
}
