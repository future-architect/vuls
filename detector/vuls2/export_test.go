package vuls2

import (
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

	CollectDefinedCPEProducts = collectDefinedCPEProducts
	CompactCPECriteria        = compactCPECriteria
	PruneAffectedDetection    = pruneAffectedDetection
	WalkPkgCriteria           = walkPkgCriteria
)

type PackStatus = packStatus

type Source source

// WarningMessages is the accumulate-then-render composition of
// collectCriteriaWarnings and renderWarningEntries, kept test-only: the
// production path (foldDetectionSeq) harvests warnings per streamed
// element instead of accumulating every tree first.
func WarningMessages(detected []detectTypes.VulnerabilityData) []string {
	var entries []warningEntry
	for _, data := range detected {
		for _, d := range data.Detections {
			for sid, conds := range d.Contents {
				for _, cond := range conds {
					entries = collectCriteriaWarnings(cond.Criteria, sid, entries)
				}
			}
		}
	}
	return renderWarningEntries(entries)
}
