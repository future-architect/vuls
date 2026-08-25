package vuls2

import (
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

func Test_collectCriteriaWarnings(t *testing.T) {
	type call struct {
		conds  []conditionTypes.FilteredCondition
		source sourceTypes.SourceID
	}
	tests := []struct {
		name  string
		calls []call
		want  []warningEntry
	}{
		{
			name: "no warnings yields none",
			calls: []call{{
				conds:  []conditionTypes.FilteredCondition{{Criteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR}}},
				source: sourceTypes.RedHatOVALv2,
			}},
			want: nil,
		},
		{
			// One entry per distinct (source, warning): duplicates collapse
			// within a tree, across trees of the same source, and from a
			// criterion nested a level down, while the same warning under
			// another source stays a separate entry.
			name: "one entry per source and warning",
			calls: []call{
				{
					source: sourceTypes.RedHatOVALv2,
					conds: []conditionTypes.FilteredCondition{
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{{
									Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
									Warnings: []warningTypes.Warning{
										{Kind: warningTypes.KindEmptyRange},
										{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-b"},
									},
								}},
							},
						},
						{
							Criteria: criteriaTypes.FilteredCriteria{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterias: []criteriaTypes.FilteredCriteria{{
									Operator: criteriaTypes.CriteriaOperatorTypeAND,
									Criterions: []criterionTypes.FilteredCriterion{{
										Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
										Warnings: []warningTypes.Warning{
											{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-b"},
											{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-a"},
										},
									}},
								}},
							},
						},
					},
				},
				{
					source: sourceTypes.RedHatCSAF,
					conds: []conditionTypes.FilteredCondition{{
						Criteria: criteriaTypes.FilteredCriteria{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: []criterionTypes.FilteredCriterion{{
								Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
								Warnings:  []warningTypes.Warning{{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-a"}},
							}},
						},
					}},
				},
			},
			want: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-b"}},
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-a"}},
				{source: sourceTypes.RedHatCSAF, warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-a"}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var entries []warningEntry
			for _, c := range tt.calls {
				for _, cond := range c.conds {
					entries = collectCriteriaWarnings(cond.Criteria, c.source, entries)
				}
			}
			if diff := gocmp.Diff(tt.want, entries, gocmp.AllowUnexported(warningEntry{}), gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("collectCriteriaWarnings() (-expected +got):\n%s", diff)
			}
		})
	}
}

func Test_mergeWarningEntries(t *testing.T) {
	tests := []struct {
		name     string
		dst, add []warningEntry
		want     []warningEntry
	}{
		{
			name: "duplicates collapse, new entries append",
			dst: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
			},
			add: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
				{source: sourceTypes.RedHatCSAF, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
			},
			want: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
				{source: sourceTypes.RedHatCSAF, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
			},
		},
		{
			name: "empty add keeps dst",
			dst: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
			},
			add: nil,
			want: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, mergeWarningEntries(tt.dst, tt.add), gocmp.AllowUnexported(warningEntry{})); diff != "" {
				t.Errorf("mergeWarningEntries() (-expected +got):\n%s", diff)
			}
		})
	}
}

func Test_renderWarningEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries []warningEntry
		want    []string
	}{
		{
			name:    "no entries yields none",
			entries: nil,
			want:    []string{},
		},
		{
			// An unset ("") cause and a cause-less kind both render kind-only
			// lines; a set cause is quoted after the kind, with the source
			// leading the parenthesized fields.
			name: "one line per entry",
			entries: []warningEntry{
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluablePackageType, Cause: ""}},
				{source: sourceTypes.RedHatOVALv2, warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-a"}},
				{source: sourceTypes.RedHatCSAF, warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range-a"}},
			},
			want: []string{
				`vuls2 skipped data it cannot evaluate (source: redhat-ovalv2, kind: empty-range). Detection may be incomplete; updating vuls may resolve this.`,
				`vuls2 skipped data it cannot evaluate (source: redhat-ovalv2, kind: unevaluable-package-type). Detection may be incomplete; updating vuls may resolve this.`,
				`vuls2 skipped data it cannot evaluate (source: redhat-ovalv2, kind: unevaluable-range-type, cause: "future-range-a"). Detection may be incomplete; updating vuls may resolve this.`,
				`vuls2 skipped data it cannot evaluate (source: redhat-csaf, kind: unevaluable-range-type, cause: "future-range-a"). Detection may be incomplete; updating vuls may resolve this.`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := gocmp.Diff(tt.want, renderWarningEntries(tt.entries)); diff != "" {
				t.Errorf("renderWarningEntries() (-expected +got):\n%s", diff)
			}
		})
	}
}
