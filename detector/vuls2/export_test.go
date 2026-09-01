package vuls2

import (
	"iter"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
)

var (
	ShouldDownload = shouldDownload

	PreConvertPkgs   = preConvertPkgs
	PreConvertCPEs   = preConvertCPEs
	PostConvert      = postConvert
	PrunePkgCriteria = prunePkgCriteria
	Enrich           = enrich
	EnrichCTI        = enrichCTI

	WalkCPECriteria      = walkCPECriteria
	MergeIntoScannedCves = mergeIntoScannedCves
	MergeVulnInfo        = mergeVulnInfo

	CollectVerifiedProducts = collectVerifiedProducts

	ProjectOSPkgDetection = projectOSPkgDetection
	ProjectCPEDetection   = projectCPEDetection
	ProjectCPECriteria    = projectCPECriteria
)

type Source source

type (
	ProjectedDetection = projectedDetection
	ProjectedCondition = projectedCondition
	VulnData           = vulnerabilityData
	DetectResult       = detectResult
)

// WarningEntry mirrors warningEntry with exported fields so the external
// test package can construct and compare entries; the exported warning
// helpers below map between the two.
type WarningEntry struct {
	Source  sourceTypes.SourceID
	Warning warningTypes.Warning
}

func toWarningEntries(entries []WarningEntry) []warningEntry {
	if entries == nil {
		return nil
	}
	es := make([]warningEntry, 0, len(entries))
	for _, e := range entries {
		es = append(es, warningEntry{source: e.Source, warning: e.Warning})
	}
	return es
}

func fromWarningEntries(entries []warningEntry) []WarningEntry {
	if entries == nil {
		return nil
	}
	es := make([]WarningEntry, 0, len(entries))
	for _, e := range entries {
		es = append(es, WarningEntry{Source: e.source, Warning: e.warning})
	}
	return es
}

func CollectCriteriaWarnings(fca criteriaTypes.FilteredCriteria, sid sourceTypes.SourceID, entries []WarningEntry) []WarningEntry {
	return fromWarningEntries(collectCriteriaWarnings(fca, sid, toWarningEntries(entries)))
}

func MergeWarningEntries(dst, add []WarningEntry) []WarningEntry {
	return fromWarningEntries(mergeWarningEntries(toWarningEntries(dst), toWarningEntries(add)))
}

func RenderWarningEntries(entries []WarningEntry) []string {
	return renderWarningEntries(toWarningEntries(entries))
}

// ProjectDetectResult converts a raw detectTypes.DetectResult fixture into
// the fold-projected form detect() produces, using the production
// projectors. Only Test_postConvert uses it: that test is deliberately a
// package-level end-to-end check from raw DB trees to VulnInfos, while
// the walk / collectVerifiedProducts / projector tests are unit tests
// over their real (projected) input forms.
func ProjectDetectResult(detected detectTypes.DetectResult) (detectResult, error) {
	out := detectResult{Detected: make([]vulnerabilityData, 0, len(detected.Detected))}
	for _, v := range detected.Detected {
		ds := make([]projectedDetection, 0, len(v.Detections))
		for _, d := range v.Detections {
			if d.Ecosystem == ecosystemTypes.EcosystemTypeCPE {
				p, err := projectCPEDetection(d)
				if err != nil {
					return detectResult{}, err
				}
				ds = append(ds, p)
				continue
			}
			p, err := projectOSPkgDetection(d)
			if err != nil {
				return detectResult{}, err
			}
			ds = append(ds, p)
		}
		out.Detected = append(out.Detected, vulnerabilityData{
			ID:              v.ID,
			Detections:      ds,
			Advisories:      v.Advisories,
			Vulnerabilities: v.Vulnerabilities,
		})
	}
	return out, nil
}

// FoldDetectionSeq exposes foldDetectionSeq with the warning entries
// mapped to their exported mirror.
func FoldDetectionSeq(seq iter.Seq2[detectTypes.RootDetection, error], project func(detectTypes.VulnerabilityDataDetection) (projectedDetection, bool, error)) (map[dataTypes.RootID]projectedDetection, []WarningEntry, error) {
	m, entries, err := foldDetectionSeq(seq, project)
	return m, fromWarningEntries(entries), err
}
