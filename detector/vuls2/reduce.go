package vuls2

import (
	"golang.org/x/xerrors"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
)

// pruneUnaffectedDetection reduces an ospkg-ecosystem detection streamed out
// of vuls2 to its affected branches: each condition's criteria tree is
// pruned with prunePkgCriteria (the same AND/OR gate walkPkgCriteria
// applies before its walk, so the pruning is invisible downstream —
// prunePkgCriteria is idempotent), conditions whose tree prunes to empty
// are dropped, and sources with no remaining conditions are removed. The
// caller drops rootIDs whose Contents end up empty. Evaluation warnings
// must be harvested from the full tree before calling this — pruned
// branches carry them away.
func pruneUnaffectedDetection(d detectTypes.VulnerabilityDataDetection) (detectTypes.VulnerabilityDataDetection, error) {
	contents := make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition, len(d.Contents))
	for sourceID, conds := range d.Contents {
		kept := make([]conditionTypes.FilteredCondition, 0, len(conds))
		for _, cond := range conds {
			pruned, err := prunePkgCriteria(cond.Criteria)
			if err != nil {
				return detectTypes.VulnerabilityDataDetection{}, xerrors.Errorf("prune criteria: %w", err)
			}
			if len(pruned.Criterias) == 0 && len(pruned.Criterions) == 0 {
				continue
			}
			cond.Criteria = pruned
			kept = append(kept, cond)
		}
		if len(kept) > 0 {
			contents[sourceID] = kept
		}
	}
	d.Contents = contents
	return d, nil
}

// compactCPEDetection reduces a cpe-ecosystem detection streamed out of
// vuls2 to a compact projection preserving exactly what this package reads
// downstream, dropping the bulk of the decoded DB payload (deep AND/OR
// nesting, version ranges, full CPEMatches enumerations):
//
//   - walkCPECriteria folds AND and OR identically and reads only the
//     vulnerable flag and Accepts of CPE criterions (after pruning
//     non-vulnerable / non-CPE criterions), so the tree structure carries
//     no information. Vulnerable criterions with a non-empty Accepts are
//     kept flat under a single OR root, Accepts intact, in the walk's DFS
//     order (children before own criterions) so folded CPE lists keep
//     their order.
//   - collectDefinedCPEProducts reads every criterion's DEFINED
//     part:vendor:product (criterion CPE and CPEMatches, matched or not)
//     for the verified-product suppression. Kept criterions carry their
//     own CPE / CPEMatches reduced to part:vendor:product form; products
//     defined only by dropped criterions are appended as vulnerable=false
//     carrier criterions holding just the product CPE, in unspecified
//     order — collectDefinedCPEProducts folds them into a set and
//     walkCPECriteria never reads non-vulnerable criterions.
//   - Contents keys (hasSuppressedCPESource, per-rootID vulnerability-data
//     narrowing) and condition Tags are untouched: no condition, source,
//     or rootID is dropped.
//
// Evaluation warnings must be harvested from the full tree before calling
// this — the projection does not carry them.
func compactCPEDetection(d detectTypes.VulnerabilityDataDetection) detectTypes.VulnerabilityDataDetection {
	contents := make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition, len(d.Contents))
	for sourceID, fconds := range d.Contents {
		compacted := make([]conditionTypes.FilteredCondition, 0, len(fconds))
		for _, fcond := range fconds {
			fcond.Criteria = compactCPECriteria(fcond.Criteria)
			compacted = append(compacted, fcond)
		}
		contents[sourceID] = compacted
	}
	d.Contents = contents
	return d
}

func compactCPECriteria(ca criteriaTypes.FilteredCriteria) criteriaTypes.FilteredCriteria {
	var (
		kept    []criterionTypes.FilteredCriterion
		carried = make(map[string]struct{})
		pending = make(map[string]struct{})
	)

	var collect func(c criteriaTypes.FilteredCriteria)
	collect = func(c criteriaTypes.FilteredCriteria) {
		for _, child := range c.Criterias {
			collect(child)
		}
		for _, cn := range c.Criterions {
			if cn.Criterion.Type != criterionTypes.CriterionTypeCPE || cn.Criterion.CPE == nil {
				continue
			}

			if cn.Criterion.CPE.Vulnerable && (len(cn.Accepts.CPE.Exact) > 0 || len(cn.Accepts.CPE.VersionUnconfirmed) > 0) {
				compact := ccTypes.Criterion{Vulnerable: true}
				if p, ok := productCPE(string(cn.Criterion.CPE.CPE)); ok {
					compact.CPE = ccTypes.CPE(p)
					carried[p] = struct{}{}
				} else {
					compact.CPE = cn.Criterion.CPE.CPE
				}
				for _, m := range cn.Criterion.CPE.CPEMatches {
					p, ok := productCPE(string(m))
					if !ok {
						continue
					}
					if _, ok := carried[p]; ok {
						continue
					}
					carried[p] = struct{}{}
					compact.CPEMatches = append(compact.CPEMatches, ccTypes.CPE(p))
				}
				kept = append(kept, criterionTypes.FilteredCriterion{
					Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &compact},
					Accepts:   criterionTypes.AcceptQueries{CPE: cn.Accepts.CPE},
				})
				continue
			}

			if p, ok := productCPE(string(cn.Criterion.CPE.CPE)); ok {
				pending[p] = struct{}{}
			}
			for _, m := range cn.Criterion.CPE.CPEMatches {
				if p, ok := productCPE(string(m)); ok {
					pending[p] = struct{}{}
				}
			}
		}
	}
	collect(ca)

	compacted := criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR, Criterions: kept}
	for p := range pending {
		if _, ok := carried[p]; ok {
			continue
		}
		compacted.Criterions = append(compacted.Criterions, criterionTypes.FilteredCriterion{
			Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &ccTypes.Criterion{CPE: ccTypes.CPE(p)}},
		})
	}
	return compacted
}

// productCPE reduces a CPE 2.3 FS string to its part:vendor:product form
// (every other attribute ANY), the granularity cpeProductKey and the
// cpe.Detect index operate at. The boolean is false when the input is not a
// valid CPE 2.3 FS string — such entries contribute nothing downstream.
func productCPE(cpe string) (string, bool) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", false
	}
	out := common.NewWellFormedName()
	out[common.AttributePart] = wfn.Get(common.AttributePart)
	out[common.AttributeVendor] = wfn.Get(common.AttributeVendor)
	out[common.AttributeProduct] = wfn.Get(common.AttributeProduct)
	return naming.BindToFS(out), true
}
