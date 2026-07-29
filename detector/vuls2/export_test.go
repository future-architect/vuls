package vuls2

var (
	ShouldDownload = shouldDownload
	MustFetchSync  = mustFetchSync

	PreConvertPkgs   = preConvertPkgs
	PreConvertCPEs   = preConvertCPEs
	PostConvert      = postConvert
	PrunePkgCriteria = prunePkgCriteria
	Enrich           = enrich
	EnrichCTI        = enrichCTI

	WalkCPECriteria      = walkCPECriteria
	MergeIntoScannedCves = mergeIntoScannedCves

	CollectVerifiedProducts = collectVerifiedProducts

	WarningMessages = warningMessages
)

type Source source

// BgFetchDownloading exposes the downloading state for tests.
func BgFetchDownloading() bool {
	bgFetch.mu.Lock()
	defer bgFetch.mu.Unlock()
	return bgFetch.downloading
}

// ResetBgFetch resets the background fetch state between tests.
func ResetBgFetch() {
	bgFetch.mu.Lock()
	bgFetch.downloading = false
	bgFetch.mu.Unlock()
}
