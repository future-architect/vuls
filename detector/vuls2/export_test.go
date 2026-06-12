package vuls2

var (
	ShouldDownload = shouldDownload

	PreConvertPkgs = preConvertPkgs
	PreConvertCPEs = preConvertCPEs
	PostConvert    = postConvert
	PruneCriteria  = pruneCriteria
	Enrich         = enrich

	WalkCPECriteria            = walkCPECriteria
	RangeVendorProductEligible = rangeVendorProductEligible
	MergeIntoScannedCves       = mergeIntoScannedCves
)

type Source source
