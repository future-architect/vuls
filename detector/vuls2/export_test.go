package vuls2

import "github.com/MaineK00n/vuls2/pkg/db/fetch"

var (
	ShouldDownload = shouldDownload
	NewDBConfig    = newDBConfig

	PreConvert    = preConvert
	PostConvert   = postConvert
	PruneCriteria = pruneCriteria
	Enrich        = enrich
)

type Source source

// SetFetchDB replaces the package-level db fetch function with f and returns a
// function that restores the original.
func SetFetchDB(f func(...fetch.Option) error) func() {
	orig := fetchDB
	fetchDB = f
	return func() { fetchDB = orig }
}
