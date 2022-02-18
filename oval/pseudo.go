package oval

import "github.com/future-architect/vuls/models"

// Pseudo is OVAL client except for Windows, FreeBSD and Pseudo
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

func (pse Pseudo) FillWithOval(r *models.ScanResult) (int, error) {
	return 0, nil
}
