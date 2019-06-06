package models

import (
	"github.com/knqyf263/go-dep-parser/pkg/types"
)

// LibraryScanner has libraries information
type LibraryScanner struct {
	Path string
	Libs []types.Library
}
