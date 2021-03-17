// +build !scanner

package gost

import (
	"github.com/future-architect/vuls/models"
)

// Pseudo is Gost client except for RedHat family and Debian
type Pseudo struct {
	Base
}

// DetectUnfixed fills cve information that has in Gost
func (pse Pseudo) DetectUnfixed(r *models.ScanResult, _ bool) (int, error) {
	return 0, nil
}
