//go:build !scanner

package vuls2_test

import (
	"testing"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	gocmp "github.com/google/go-cmp/cmp"

	"github.com/future-architect/vuls/detector/vuls2"
)

// Test_walkCPECriteria documents the CPE confidence-tier rules as a table,
// one case per rule. The rules replicate the observable behaviour of
// go-cve-dictionary's CPE matching (db/db.go match() and the JVN-style
// part:vendor:product handling) so that, once go-cve-dictionary is archived,
// this table — not its source — is the reference:
//
//   - exact tier: a criterion with a version restriction accepted
//   - vendor:product tier: the condition only confirms part:vendor:product —
//     an accept by a version-unrestricted criterion, a criterion/query
//     without version information (NA/ANY), or a range only RPM comparison
//     can place in-range (gocve's matchRpmVer fallback, formerly Rough)
//   - nothing: definitive misses (concrete version mismatch, confirmed out
//     of range, enumeration miss) — gocve never reported these either
func Test_walkCPECriteria(t *testing.T) {
	// cn builds a vulnerable=true CPE criterion; accepts carries the
	// scanned.CPE indexes the detect step accepted (nil = no accept).
	cn := func(cpe string, rng *ccRangeTypes.Range, matches []ccTypes.CPE, accepts []int) criterionTypes.FilteredCriterion {
		return criterionTypes.FilteredCriterion{
			Criterion: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					CPE:        ccTypes.CPE(cpe),
					Range:      rng,
					CPEMatches: matches,
				},
			},
			Accepts: criterionTypes.AcceptQueries{CPE: accepts},
		}
	}
	guard := func(cpe string) criterionTypes.FilteredCriterion {
		c := cn(cpe, nil, nil, nil)
		c.Criterion.CPE.Vulnerable = false
		return c
	}
	or := func(cns ...criterionTypes.FilteredCriterion) criteriaTypes.FilteredCriteria {
		return criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR, Criterions: cns}
	}
	and := func(cns ...criterionTypes.FilteredCriterion) criteriaTypes.FilteredCriteria {
		return criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeAND, Criterions: cns}
	}
	semverLT := func(v string) *ccRangeTypes.Range {
		return &ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: v}
	}

	const (
		scanned990    = "cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"
		scannedJunos  = "cpe:2.3:o:vendor:product:21.4r3:*:*:*:*:*:*:*"
		scannedNoVer  = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
		crConcrete990 = "cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"
		crConcrete100 = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"
		crAny         = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
		crAnyOS       = "cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*"
		crNA          = "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"
		crOther       = "cpe:2.3:a:othervendor:otherproduct:1.0:*:*:*:*:*:*:*"
	)

	tests := []struct {
		name      string
		criteria  criteriaTypes.FilteredCriteria
		scanned   []string
		wantExact []string
		wantVP    []string
	}{
		// --- accepted criteria ---
		{
			name:      "accepted with version restriction (concrete version) -> exact",
			criteria:  or(cn(crConcrete990, nil, nil, []int{0})),
			scanned:   []string{scanned990},
			wantExact: []string{scanned990},
		},
		{
			name:      "accepted with version restriction (in-range) -> exact",
			criteria:  or(cn(crAny, semverLT("10.0"), nil, []int{0})),
			scanned:   []string{scanned990},
			wantExact: []string{scanned990},
		},
		{
			name:     "accepted without any version restriction (bare ANY, the JVN shape) -> vendor:product",
			criteria: or(cn(crAny, nil, nil, []int{0})),
			scanned:  []string{scanned990},
			wantVP:   []string{scanned990},
		},
		{
			name:     "accepted via the version=NA short-circuit -> vendor:product",
			criteria: or(cn(crNA, nil, nil, []int{0})),
			scanned:  []string{scanned990},
			wantVP:   []string{scanned990},
		},
		// --- not accepted, but not definitively missed ---
		{
			name:     "no accept, criterion version NA -> vendor:product",
			criteria: or(cn(crNA, nil, nil, nil)),
			scanned:  []string{scanned990},
			wantVP:   []string{scanned990},
		},
		{
			name:     "no accept, query without version -> vendor:product",
			criteria: or(cn(crConcrete100, nil, nil, nil)),
			scanned:  []string{scannedNoVer},
			wantVP:   []string{scannedNoVer},
		},
		{
			name:     "no accept, range incomparable but RPM-in-range (junos 21.4r3 < 22.2) -> vendor:product",
			criteria: or(cn(crAnyOS, semverLT("22.2"), nil, nil)),
			scanned:  []string{scannedJunos},
			wantVP:   []string{scannedJunos},
		},
		// --- definitive misses: report nothing ---
		{
			name:     "no accept, concrete version mismatch -> nothing",
			criteria: or(cn(crConcrete100, nil, nil, nil)),
			scanned:  []string{scanned990},
		},
		{
			name:     "no accept, confirmed out of range -> nothing",
			criteria: or(cn(crAny, semverLT("5.0"), nil, nil)),
			scanned:  []string{scanned990},
		},
		{
			name:     "no accept, range incomparable and RPM-out-of-range -> nothing",
			criteria: or(cn(crAnyOS, semverLT("21.0"), nil, nil)),
			scanned:  []string{scannedJunos},
		},
		{
			name:     "no accept, enumeration (CPEMatches-only) miss -> nothing",
			criteria: or(cn(crAny, nil, []ccTypes.CPE{ccTypes.CPE(crConcrete100)}, nil)),
			scanned:  []string{scanned990},
		},
		{
			name:     "different vendor:product -> nothing",
			criteria: or(cn(crOther, nil, nil, nil)),
			scanned:  []string{scanned990},
		},
		{
			name:     "vulnerable=false guard alone -> nothing",
			criteria: or(guard(crNA)),
			scanned:  []string{scanned990},
		},
		// --- AND / OR structure ---
		{
			name:      "OR(exact, vendor:product) keeps both tiers",
			criteria:  or(cn(crConcrete990, nil, nil, []int{0}), cn(crNA, nil, nil, nil)),
			scanned:   []string{scanned990},
			wantExact: []string{scanned990},
			wantVP:    []string{scanned990},
		},
		{
			name:     "AND(exact, vendor:product) demotes the conjunction to vendor:product",
			criteria: and(cn(crConcrete990, nil, nil, []int{0}), cn(crNA, nil, nil, nil)),
			scanned:  []string{scanned990},
			wantVP:   []string{scanned990},
		},
		{
			name:     "AND(exact, definitive miss) reports nothing",
			criteria: and(cn(crConcrete990, nil, nil, []int{0}), cn(crConcrete100, nil, nil, nil)),
			scanned:  []string{scanned990},
		},
		{
			name:      "AND with a vulnerable=false guard: the guard is neutral",
			criteria:  and(cn(crConcrete990, nil, nil, []int{0}), guard("cpe:2.3:h:vendor:hardware:-:*:*:*:*:*:*:*")),
			scanned:   []string{scanned990},
			wantExact: []string{scanned990},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exact, vp, err := vuls2.WalkCPECriteria(tt.criteria, scanTypes.ScanResult{CPE: tt.scanned})
			if err != nil {
				t.Fatalf("walkCPECriteria() error = %v", err)
			}
			if diff := gocmp.Diff(exact, tt.wantExact); diff != "" {
				t.Errorf("exact mismatch (-got +want):\n%s", diff)
			}
			if diff := gocmp.Diff(vp, tt.wantVP); diff != "" {
				t.Errorf("vendor:product mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

// Test_rangeVendorProductEligible pins the bound-by-bound behaviour: a bound
// the range's comparator can evaluate rejects on a confirmed out-of-range,
// and an incomparable pair falls back to RPM-style comparison —
// go-cve-dictionary's matchRpmVer fallback, false-positive tolerance
// included.
func Test_rangeVendorProductEligible(t *testing.T) {
	tests := []struct {
		name string
		r    ccRangeTypes.Range
		qv   string
		want bool
	}{
		{name: "lt: inside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "10.0"}, qv: "9.9.9", want: true},
		{name: "lt: outside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "5.0"}, qv: "9.9.9", want: false},
		{name: "le: boundary inside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessEqual: "9.9.9"}, qv: "9.9.9", want: true},
		{name: "lt: boundary outside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "9.9.9"}, qv: "9.9.9", want: false},
		{name: "ge: inside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "9.9.9"}, qv: "9.9.9", want: true},
		{name: "gt: boundary outside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterThan: "9.9.9"}, qv: "9.9.9", want: false},
		{name: "ge+lt window: inside", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "5.0", LessThan: "10.0"}, qv: "9.9.9", want: true},
		{name: "ge+lt window: below", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, GreaterEqual: "5.0", LessThan: "10.0"}, qv: "1.0", want: false},
		{name: "incomparable query, RPM fallback in-range (21.4r3 < 22.2)", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "22.2"}, qv: "21.4r3", want: true},
		{name: "incomparable query, RPM fallback out-of-range (21.4r3 >= 21.0)", r: ccRangeTypes.Range{Type: ccRangeTypes.RangeTypeSEMVER, LessThan: "21.0"}, qv: "21.4r3", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vuls2.RangeVendorProductEligible(&tt.r, tt.qv); got != tt.want {
				t.Errorf("rangeVendorProductEligible() = %v, want %v", got, tt.want)
			}
		})
	}
}
