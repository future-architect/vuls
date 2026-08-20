package vuls2

import "github.com/MaineK00n/vuls2/pkg/db/session"

// Open exposes Session.open so tests can force the lazy open and inspect what
// it produced.
func (s *Session) Open() (*session.Session, error) { return s.open() }

// SkipsUpdate reports whether this Session is barred from downloading a db, so
// a test can assert that the request path cannot fetch.
func (s *Session) SkipsUpdate() bool { return s.vuls2Conf.SkipUpdate }

var (
	ShouldDownload = shouldDownload
	HasNewerRemote = hasNewerRemote

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
