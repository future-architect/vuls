package scan

import (
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// inherit OsTypeInterface
type pseudo struct {
	base
}

func detectPseudo(c config.ServerInfo) (itsMe bool, pseudo osTypeInterface, err error) {
	p := newPseudo(c)
	p.setDistro(config.ServerTypePseudo, "")
	return c.Type == config.ServerTypePseudo, p, nil
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
	d.log = util.NewCustomLogger(c)
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
