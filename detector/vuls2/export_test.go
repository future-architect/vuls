package vuls2

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

	WarningMessages = warningMessages

	CollectDefinedCPEProducts = collectDefinedCPEProducts
	CompactCPECriteria        = compactCPECriteria
	PruneAffectedDetection    = pruneAffectedDetection
	WalkPkgCriteria           = walkPkgCriteria
)

type PackStatus = packStatus

type Source source
