package scanner

import "github.com/future-architect/vuls/models"

// inherit OsTypeInterface
type unknown struct {
	base
}

func (o *unknown) checkScanMode() error {
	return nil
}

func (o *unknown) checkIfSudoNoPasswd() error {
	return nil
}

func (o *unknown) checkDeps() error {
	return nil
}

func (o *unknown) preCure() error {
	return nil
}

func (o *unknown) postScan() error {
	return nil
}

func (o *unknown) scanPackages() error {
	return nil
}

func (o *unknown) parseInstalledPackages(string) (models.Packages, models.SrcPackages, error) {
	return nil, nil, nil
}
