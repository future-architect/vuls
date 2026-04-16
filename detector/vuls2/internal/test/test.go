package test

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/db/session"
)

// PopulateDB populates the database specified by c with test data from fixtureDir.
// Children of fixtureDir are datasource directories, each has "datasource.json" file and "data/" directory.
func PopulateDB(c session.Config, fixtureDir string) error {
	if c.Path == "" {
		return errors.New("Config.Path must not be empty")
	}

	if fixtureDir == "" {
		return errors.New("fixtureDir must not be empty")
	}

	s, err := c.New()
	if err != nil {
		return errors.Wrap(err, "new db connection")
	}

	if err := s.Storage().Open(); err != nil {
		return errors.Wrap(err, "open db connection")
	}
	defer s.Storage().Close()
	defer s.Cache().Close()

	if err := s.Storage().Initialize(); err != nil {
		return errors.Wrap(err, "initialize")
	}

	datasources, err := os.ReadDir(fixtureDir)
	if err != nil {
		return err
	}

	for _, ds := range datasources {
		if err := s.Storage().Put(filepath.Join(fixtureDir, ds.Name())); err != nil {
			return errors.Wrapf(err, "put %s", ds.Name())
		}
	}

	return nil
}
