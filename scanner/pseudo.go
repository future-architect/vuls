package scanner

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/logging"
	"github.com/future-architect/vuls/models"
)

// inherit OsTypeInterface
type pseudo struct {
	base
}

func detectPseudo(c config.ServerInfo) (itsMe bool, pseudo osTypeInterface, err error) {
	if c.Type == constant.ServerTypePseudo {
		p := newPseudo(c)
		p.setDistro(constant.ServerTypePseudo, "")
		return true, p, nil
	}
	return false, nil, nil
}

func newPseudo(c config.ServerInfo) *pseudo {
	d := &pseudo{
		base: base{
			osPackages: osPackages{
				Packages:  models.Packages{},
				VulnInfos: models.VulnInfos{},
			},
		},
	}
	d.log = logging.NewNormalLogger()
	d.setServerInfo(c)
	return d
}

func (o *pseudo) checkScanMode() error {
	return nil
}

func (o *pseudo) checkIfSudoNoPasswd() error {
	return nil
}

func (o *pseudo) checkDeps() error {
	return nil
}

func (o *pseudo) preCure() error {
	return nil
}

func (o *pseudo) postScan() error {
	return nil
}

func (o *pseudo) scanPackages() error {
	return nil
}

func (o *pseudo) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}

func (o *pseudo) detectPlatform() {
	o.setPlatform(models.Platform{Name: "other"})
	return
}
