//go:build !scanner
// +build !scanner

package gost

import (
	"github.com/future-architect/vuls/models"
)

// Pseudo is Gost client except for RedHat family, Debian, Ubuntu and Windows
type Pseudo struct {
	Base
}

// DetectCVEs fills cve information that has in Gost
func (pse Pseudo) DetectCVEs(_ *models.ScanResult, _ bool) (int, error) {
	return 0, nil
}
