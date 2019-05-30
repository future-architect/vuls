package models

import (
	"github.com/knqyf263/go-dep-parser/pkg/types"
)

type LibraryScanner struct {
	Path string
	Libs []types.Library
}
