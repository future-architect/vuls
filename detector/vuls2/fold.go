package vuls2

import (
	"context"
	"iter"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"

	"fmt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"

	"maps"
	"slices"
)

// projectedDetection is one rootID's detection reduced by the fold to exactly what
// this package reads downstream — the common shape both ecosystems' folds
// produce, and the contract between detect() and postConvert: everything
// postConvert needs from a full vuls2 criteria tree is extracted here,
// before the tree is dropped.
type projectedDetection struct {
	Ecosystem ecosystemTypes.Ecosystem
	Contents  map[sourceTypes.SourceID][]projectedCondition
}

// projectedCondition is one source condition reduced to what its ecosystem's walk
// reads. Criteria is walk-ready for the ecosystem's walker: pkg — the
// gate-pruned tree (prunePkgCriteria's AND/OR gate over detect-time
// accepts, applied here and nowhere else); cpe — the flat projection of
// vulnerable+accepted criterions (walkCPECriteria assumes both).
// DefinedProducts is cpe-only (always nil for pkg): the
// part:vendor:product keys every criterion of the full tree DEFINES,
// matched or not — the verified-product suppression input, aggregated
// across roots by postConvert's collectVerifiedProducts.
type projectedCondition struct {
	Criteria        criteriaTypes.FilteredCriteria
	Tag             segmentTypes.DetectionTag
	DefinedProducts []string
}

// vulnerabilityData is projectedDetection plus the fetched Advisory/Vulnerability
// contents for the rootID — the per-root element of detectResult.
type vulnerabilityData struct {
	ID              dataTypes.RootID
	Detections      []projectedDetection
	Advisories      []dbTypes.VulnerabilityDataAdvisory
	Vulnerabilities []dbTypes.VulnerabilityDataVulnerability
}

// detectResult is detect()'s in-memory result, consumed by postConvert.
type detectResult struct {
	Detected []vulnerabilityData
}

type warningEntry struct {
	source  sourceTypes.SourceID
	warning warningTypes.Warning
}

// collectCriteriaWarnings appends the (source, warning) pairs recorded on
// fca's criterions to entries, skipping pairs already present (deduplicated
// with the upstream warning.Compare), and returns the updated slice. These
// are the non-fatal evaluation warnings for data this build could not
// evaluate (e.g. produced by a newer vuls-data-update); vuls2 hands the
// trees over ungated with out-of-vocabulary criterions carrying their
// recorded warnings, so even a condition whose every criterion was skipped
// is represented. The streaming detect fold calls this on each full tree
// before reducing it — the reductions could otherwise drop the warnings
// along with the criterions carrying them.
func collectCriteriaWarnings(fca criteriaTypes.FilteredCriteria, sid sourceTypes.SourceID, entries []warningEntry) []warningEntry {
	for _, ca := range fca.Criterias {
		entries = collectCriteriaWarnings(ca, sid, entries)
	}
	for _, cn := range fca.Criterions {
		for _, w := range cn.Warnings {
			e := warningEntry{source: sid, warning: w}
			if !slices.ContainsFunc(entries, func(x warningEntry) bool {
				return x.source == e.source && warningTypes.Compare(x.warning, e.warning) == 0
			}) {
				entries = append(entries, e)
			}
		}
	}
	return entries
}

// mergeWarningEntries appends the entries of add not already present in
// dst (same (source, warning) dedup as collectCriteriaWarnings) and
// returns the updated slice.
func mergeWarningEntries(dst, add []warningEntry) []warningEntry {
	for _, e := range add {
		if !slices.ContainsFunc(dst, func(x warningEntry) bool {
			return x.source == e.source && warningTypes.Compare(x.warning, e.warning) == 0
		}) {
			dst = append(dst, e)
		}
	}
	return dst
}

// renderWarningEntries renders collected warning entries into scan-result
// warning lines, one per entry. Each line renders deterministically on its
// own, so callers can deduplicate across passes by comparing the rendered
// strings. The source leads the format on purpose —
// ScanResult.SortForJSONOutput orders the lines lexicographically, so a
// drifting source's lines cluster together, then by kind and cause. An
// empty Cause (the raw value for an unset datum, or the constant for
// cause-less kinds like empty-range) is not rendered. Line order here is
// unspecified — SortForJSONOutput normalizes it.
func renderWarningEntries(entries []warningEntry) []string {
	msgs := make([]string, 0, len(entries))
	for _, e := range entries {
		var parts []string
		if e.source != "" {
			parts = append(parts, fmt.Sprintf("source: %s", e.source))
		}
		parts = append(parts, fmt.Sprintf("kind: %s", e.warning.Kind))
		if e.warning.Cause != "" {
			parts = append(parts, fmt.Sprintf("cause: %q", e.warning.Cause))
		}
		msgs = append(msgs, fmt.Sprintf("vuls2 skipped data it cannot evaluate (%s). Detection may be incomplete; updating vuls may resolve this.", strings.Join(parts, ", ")))
	}
	return msgs
}

// foldDetectionSeq consumes a detection stream with a pool of fold
// workers: each element's evaluation warnings are harvested from the full
// tree, then project reduces the tree to a detection (returning
// keep=false to drop the rootID entirely) — typically one of the
// project* functions below plus the caller's keep policy. Folding in
// parallel matters — the stream
// side runs NumCPU workers, and a single consumer goroutine walking every
// large tree (e.g. cpe_kernel's) becomes the pipeline bottleneck. Peak
// memory holds the folded result plus only the in-flight full trees
// (stream workers + channel buffer + fold workers, each bounded by
// NumCPU).
func foldDetectionSeq(seq iter.Seq2[util.RootDetection, error], project func(detectTypes.VulnerabilityDataDetection) (projectedDetection, bool, error)) (map[dataTypes.RootID]projectedDetection, []warningEntry, error) {
	var (
		mu          sync.Mutex
		m           = make(map[dataTypes.RootID]projectedDetection)
		warnEntries []warningEntry
	)

	// gctx is canceled by the first worker error, so the consumer loop
	// below stops draining the stream: breaking out of the range cancels
	// vuls2's producer, and an early project failure does not pay for the
	// remaining roots' DB fetches and evaluations.
	g, gctx := errgroup.WithContext(context.Background())
	g.SetLimit(runtime.NumCPU())
	var seqErr error
	for rd, err := range seq {
		if err != nil {
			seqErr = err
			break
		}
		if gctx.Err() != nil {
			break
		}
		g.Go(func() error {
			// The loop's check above is not atomic with g.Go: with SetLimit,
			// g.Go blocks while every slot is taken, and a cancellation
			// arriving during that wait would otherwise let this element be
			// projected once a slot opens. Re-check before doing any work.
			if err := gctx.Err(); err != nil {
				return err
			}

			var entries []warningEntry
			for sid, conds := range rd.Detection.Contents {
				for _, cond := range conds {
					entries = collectCriteriaWarnings(cond.Criteria, sid, entries)
				}
			}

			d, keep, err := project(rd.Detection)
			if err != nil {
				return xerrors.Errorf("fold detection. RootID: %s, err: %w", rd.RootID, err)
			}

			mu.Lock()
			defer mu.Unlock()
			warnEntries = mergeWarningEntries(warnEntries, entries)
			if keep {
				m[rd.RootID] = d
			}
			return nil
		})
	}
	// Join the fold workers before returning either way. A stream error
	// outranks a worker error: the workers consume what the stream
	// produced, so the stream side is the root cause when both fail.
	werr := g.Wait()
	if seqErr != nil {
		return nil, nil, seqErr
	}
	if werr != nil {
		return nil, nil, werr
	}
	return m, warnEntries, nil
}

// projectOSPkgDetection reduces an ospkg-ecosystem detection streamed out
// of vuls2 to its affected branches: each condition's criteria tree is
// gate-pruned with prunePkgCriteria, conditions whose tree prunes to
// empty are dropped, and sources with no remaining conditions are
// removed. The caller drops rootIDs whose Contents end up empty. The
// cpe-ecosystem counterpart is projectCPEDetection.
func projectOSPkgDetection(d detectTypes.VulnerabilityDataDetection) (projectedDetection, error) {
	contents := make(map[sourceTypes.SourceID][]projectedCondition, len(d.Contents))
	for sourceID, fconds := range d.Contents {
		kept := make([]projectedCondition, 0, len(fconds))
		for _, fcond := range fconds {
			pruned, err := prunePkgCriteria(fcond.Criteria)
			if err != nil {
				return projectedDetection{}, xerrors.Errorf("prune criteria: %w", err)
			}
			if len(pruned.Criterias) == 0 && len(pruned.Criterions) == 0 {
				continue
			}
			kept = append(kept, projectedCondition{Criteria: pruned, Tag: fcond.Tag})
		}
		if len(kept) > 0 {
			contents[sourceID] = kept
		}
	}
	return projectedDetection{Ecosystem: d.Ecosystem, Contents: contents}, nil
}

// projectCPEDetection reduces a cpe-ecosystem detection streamed out of
// vuls2 via projectCPECriteria, per condition. Unlike the ospkg side, no
// condition, source, or rootID is dropped: an empty walk-ready tree still
// walks to nothing, and its DefinedProducts and Contents keys
// (hasSuppressedCPESource, per-rootID vulnerability-data narrowing) stay
// meaningful. The ospkg-ecosystem counterpart is projectOSPkgDetection.
func projectCPEDetection(d detectTypes.VulnerabilityDataDetection) (projectedDetection, error) {
	contents := make(map[sourceTypes.SourceID][]projectedCondition, len(d.Contents))
	for sourceID, fconds := range d.Contents {
		conds := make([]projectedCondition, 0, len(fconds))
		for _, fcond := range fconds {
			walkReady, defined, err := projectCPECriteria(fcond.Criteria)
			if err != nil {
				return projectedDetection{}, xerrors.Errorf("project criteria: %w", err)
			}
			conds = append(conds, projectedCondition{Criteria: walkReady, Tag: fcond.Tag, DefinedProducts: defined})
		}
		contents[sourceID] = conds
	}
	return projectedDetection{Ecosystem: d.Ecosystem, Contents: contents}, nil
}

// projectCPECriteria splits a cpe-ecosystem criteria tree into its two
// downstream reads, dropping the bulk of the decoded DB payload (deep
// AND/OR nesting, version ranges, full CPEMatches enumerations):
//
//   - the walk-ready tree: vulnerable criterions with a non-empty
//     Accepts, kept flat under a single OR root, Accepts intact, in DFS
//     order (children before own criterions) so folded CPE lists keep
//     their order; their CPE is reduced to part:vendor:product form for
//     debuggability (the walk reads only the Accepts) and their
//     CPEMatches are dropped. Flattening the AND/OR structure away is
//     deliberate go-cve-dictionary compatibility: it treats every
//     vulnerable=true CPE in an applicability node as independently
//     matchable, ignoring the operator, so a co-required product NVD
//     happens to mark vulnerable=true (e.g. the Xen hypervisor conjoined
//     with the vulnerable kernel in CVE-2021-28039) never vetoes the
//     kernel leg. Existing users relied on this flattening under
//     go-cve-dictionary; keeping it trades AND precision for that
//     compatibility, scoped to CPE detection only.
//   - the defined products: the part:vendor:product key of every CPE
//     criterion's own CPE and CPEMatches, kept or dropped, matched or not
//     (cond.Accept keeps non-matching criterions under
//     FilteredCriterion.Criterion) — collectVerifiedProducts' input,
//     sorted for determinism.
//
// Evaluation warnings must be harvested from the full tree before calling
// this — the projection does not carry them.
func projectCPECriteria(ca criteriaTypes.FilteredCriteria) (criteriaTypes.FilteredCriteria, []string, error) {
	var (
		kept    []criterionTypes.FilteredCriterion
		defined = make(map[string]struct{})
	)

	var collect func(c criteriaTypes.FilteredCriteria) error
	collect = func(c criteriaTypes.FilteredCriteria) error {
		// The flattening deliberately ignores which of AND/OR the node is,
		// but an operator outside that vocabulary still fails fast —
		// matching prunePkgCriteria — rather than silently taking the OR
		// path on corrupt or newer-vocabulary data.
		switch c.Operator {
		case criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR:
		default:
			return xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
		}
		for _, child := range c.Criterias {
			if err := collect(child); err != nil {
				return err
			}
		}
		for _, cn := range c.Criterions {
			if cn.Criterion.Type != criterionTypes.CriterionTypeCPE || cn.Criterion.CPE == nil {
				continue
			}

			if key, ok := cpeProductKey(string(cn.Criterion.CPE.CPE)); ok {
				defined[key] = struct{}{}
			}
			for _, m := range cn.Criterion.CPE.CPEMatches {
				if key, ok := cpeProductKey(string(m)); ok {
					defined[key] = struct{}{}
				}
			}

			if !cn.Criterion.CPE.Vulnerable || (len(cn.Accepts.CPE.Exact) == 0 && len(cn.Accepts.CPE.VersionUnconfirmed) == 0) {
				continue
			}
			compact := ccTypes.Criterion{Vulnerable: true}
			if p, ok := productCPE(string(cn.Criterion.CPE.CPE)); ok {
				compact.CPE = ccTypes.CPE(p)
			} else {
				compact.CPE = cn.Criterion.CPE.CPE
			}
			kept = append(kept, criterionTypes.FilteredCriterion{
				Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE, CPE: &compact},
				Accepts:   criterionTypes.AcceptQueries{CPE: cn.Accepts.CPE},
			})
		}
		return nil
	}
	if err := collect(ca); err != nil {
		return criteriaTypes.FilteredCriteria{}, nil, err
	}

	return criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR, Criterions: kept}, slices.Sorted(maps.Keys(defined)), nil
}

// prunePkgCriteria drops unaffected branches from a FilteredCriteria tree.
//
// AND parents fail (return empty) if any required child is unaffected, OR
// parents skip unaffected children. The vuls2 util.Detect step now passes
// every condition through unconditionally — this function is the actual
// AND/OR gate. cpe-ecosystem conditions never come through here; their
// accepts are judged by walkCPECriteria's walk instead.
func prunePkgCriteria(c criteriaTypes.FilteredCriteria) (criteriaTypes.FilteredCriteria, error) {
	pruned := criteriaTypes.FilteredCriteria{
		Operator: c.Operator,
		Criterias: func() []criteriaTypes.FilteredCriteria {
			if len(c.Criterias) > 0 {
				return make([]criteriaTypes.FilteredCriteria, 0, len(c.Criterias))
			}
			return nil
		}(),
		Criterions: func() []criterionTypes.FilteredCriterion {
			if len(c.Criterions) > 0 {
				return make([]criterionTypes.FilteredCriterion, 0, len(c.Criterions))
			}
			return nil
		}(),
	}

	for _, child := range c.Criterias {
		child, err := prunePkgCriteria(child)
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("prune criteria: %w", err)
		}

		if len(child.Criterias) == 0 && len(child.Criterions) == 0 {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return criteriaTypes.FilteredCriteria{}, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
			}
		}

		pruned.Criterias = append(pruned.Criterias, child)
	}

	for _, cn := range c.Criterions {
		isAffected, err := cn.Affected()
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("criterion affected: %w", err)
		}

		if !isAffected {
			switch c.Operator {
			case criteriaTypes.CriteriaOperatorTypeAND:
				return criteriaTypes.FilteredCriteria{}, nil
			case criteriaTypes.CriteriaOperatorTypeOR:
				continue
			default:
				return criteriaTypes.FilteredCriteria{}, xerrors.Errorf("unexpected operator. expected: %q, actual: %q", []criteriaTypes.CriteriaOperatorType{criteriaTypes.CriteriaOperatorTypeAND, criteriaTypes.CriteriaOperatorTypeOR}, c.Operator)
			}
		}

		pruned.Criterions = append(pruned.Criterions, cn)
	}

	return pruned, nil
}

// productCPE reduces a CPE 2.3 FS string to its part:vendor:product form
// (every other attribute ANY), the granularity cpeProductKey and the
// cpe.Detect index operate at. The boolean is false when the input is not
// a valid CPE 2.3 FS form.
func productCPE(cpe string) (string, bool) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", false
	}
	product := common.NewWellFormedName()
	for _, attr := range []string{common.AttributePart, common.AttributeVendor, common.AttributeProduct} {
		if err := product.Set(attr, wfn.Get(attr)); err != nil {
			return "", false
		}
	}
	return naming.BindToFS(product), true
}

// cpeProductKey returns the "part:vendor:product" key of a CPE 2.3
// formatted string, matching the index key vuls2's cpe.Detect groups
// scanned CPEs by. The boolean is false when the string is not a valid
// CPE 2.3 FS form.
func cpeProductKey(cpe string) (string, bool) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%s:%s:%s",
		wfn.GetString(common.AttributePart),
		wfn.GetString(common.AttributeVendor),
		wfn.GetString(common.AttributeProduct)), true
}
