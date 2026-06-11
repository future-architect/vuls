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
)

type Source source
