package oval

import "github.com/future-architect/vuls/models"

// Pseudo is OVAL client for Windows, FreeBSD and Pseudo
type Pseudo struct {
	Base
}

// NewPseudo creates OVAL client for Windows, FreeBSD and Pseudo
func NewPseudo(family string) Pseudo {
	return Pseudo{
		Base{
			driver:  nil,
			baseURL: "",
			family:  family,
		},
	}
}

// FillWithOval is a mock function for operating systems that do not use OVAL
func (pse Pseudo) FillWithOval(_ *models.ScanResult) (int, error) {
	return 0, nil
}
