package vuls2

import (
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
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

	CollectDefinedCPEProducts = collectDefinedCPEProducts
	CompactCPECriteria        = compactCPECriteria
	PruneUnaffectedDetection  = pruneUnaffectedDetection
	WalkPkgCriteria           = walkPkgCriteria
)

type PackStatus = packStatus

type Source source

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
