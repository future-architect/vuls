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
	bgFetch.initialDone = nil
	bgFetch.initialErr = nil
	bgFetch.mu.Unlock()
}

// SetInitialDone simulates a completed startup fetch for testing.
func SetInitialDone(err error) {
	bgFetch.mu.Lock()
	bgFetch.initialDone = make(chan struct{})
	close(bgFetch.initialDone)
	bgFetch.initialErr = err
	bgFetch.mu.Unlock()
}

// SetInitialInProgress simulates a startup fetch still in progress.
func SetInitialInProgress() {
	bgFetch.mu.Lock()
	bgFetch.initialDone = make(chan struct{})
	bgFetch.downloading = true
	bgFetch.mu.Unlock()
}
