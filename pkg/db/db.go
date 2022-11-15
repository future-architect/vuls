package db

import (
	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/db/boltdb"
	"github.com/future-architect/vuls/pkg/db/rdb"
	"github.com/future-architect/vuls/pkg/db/redis"
	"github.com/future-architect/vuls/pkg/db/types"
)

type options struct {
}

type Option interface {
	apply(*options)
}

type DB struct {
	name   string
	driver Driver
}

type Driver interface {
	Close() error

	PutVulnerability(string, string, types.Vulnerability) error
	PutPackage(string, string, map[string]types.Packages) error
	PutCPEConfiguration(string, string, map[string]types.CPEConfigurations) error
	PutRedHatRepoToCPE(string, string, types.RepositoryToCPE) error
	PutWindowsSupercedence(string, string, types.Supercedence) error

	GetVulnerability([]string) (map[string]map[string]types.Vulnerability, error)
	GetPackage(string, string, string) (map[string]map[string]map[string]types.Package, error)
	GetCPEConfiguration(string) (map[string]map[string]map[string][]types.CPEConfiguration, error)
	GetSupercedence([]string) (map[string][]string, error)
	GetKBtoProduct(string, []string) ([]string, error)
}

func (db *DB) Name() string {
	return db.name
}

func Open(dbType, dbPath string, debug bool, opts ...Option) (*DB, error) {
	switch dbType {
	case "boltdb":
		d, err := boltdb.Open(dbPath, debug)
		if err != nil {
			return nil, errors.Wrap(err, "open boltdb")
		}
		return &DB{name: dbType, driver: d}, nil
	case "sqlite3", "mysql", "postgres":
		d, err := rdb.Open(dbType, dbPath, debug)
		if err != nil {
			return nil, errors.Wrap(err, "open rdb")
		}
		return &DB{name: dbType, driver: d}, nil
	case "redis":
		d, err := redis.Open(dbPath, debug)
		if err != nil {
			return nil, errors.Wrap(err, "open rdb")
		}
		return &DB{name: dbType, driver: d}, nil
	default:
		return nil, errors.Errorf(`unexpected dbType. accepts: ["boltdb", "sqlite3", "mysql", "postgres", "redis"], received: "%s"`, dbType)
	}
}

func (db *DB) Close() error {
	if err := db.driver.Close(); err != nil {
		return errors.Wrapf(err, "close %s", db.name)
	}
	return nil
}

func (db *DB) PutVulnerability(src, key string, value types.Vulnerability) error {
	if err := db.driver.PutVulnerability(src, key, value); err != nil {
		return errors.Wrapf(err, "put vulnerability")
	}
	return nil
}

func (db *DB) PutPackage(src, key string, value map[string]types.Packages) error {
	if err := db.driver.PutPackage(src, key, value); err != nil {
		return errors.Wrapf(err, "put package")
	}
	return nil
}

func (db *DB) PutCPEConfiguration(src, key string, value map[string]types.CPEConfigurations) error {
	if err := db.driver.PutCPEConfiguration(src, key, value); err != nil {
		return errors.Wrapf(err, "put cpe configuration")
	}
	return nil
}

func (db *DB) PutRedHatRepoToCPE(src, key string, value types.RepositoryToCPE) error {
	if err := db.driver.PutRedHatRepoToCPE(src, key, value); err != nil {
		return errors.Wrap(err, "put repository to cpe")
	}
	return nil
}

func (db *DB) PutWindowsSupercedence(src, key string, value types.Supercedence) error {
	if err := db.driver.PutWindowsSupercedence(src, key, value); err != nil {
		return errors.Wrap(err, "put supercedence")
	}
	return nil
}

func (db *DB) GetVulnerability(ids []string) (map[string]map[string]types.Vulnerability, error) {
	rs, err := db.driver.GetVulnerability(ids)
	if err != nil {
		return nil, errors.Wrapf(err, "get vulnerability")
	}
	return rs, nil
}

func (db *DB) GetPackage(family, release string, name string) (map[string]map[string]map[string]types.Package, error) {
	rs, err := db.driver.GetPackage(family, release, name)
	if err != nil {
		return nil, errors.Wrapf(err, "get package")
	}
	return rs, nil
}

func (db *DB) GetCPEConfiguration(partvendorproduct string) (map[string]map[string]map[string][]types.CPEConfiguration, error) {
	rs, err := db.driver.GetCPEConfiguration(partvendorproduct)
	if err != nil {
		return nil, errors.Wrapf(err, "get cpe configuration")
	}
	return rs, nil
}

func (db *DB) GetSupercedence(kb []string) (map[string][]string, error) {
	rs, err := db.driver.GetSupercedence(kb)
	if err != nil {
		return nil, errors.Wrap(err, "get supercedence")
	}
	return rs, nil
}

func (db *DB) GetKBtoProduct(release string, kb []string) ([]string, error) {
	rs, err := db.driver.GetKBtoProduct(release, kb)
	if err != nil {
		return nil, errors.Wrap(err, "get product from kb")
	}
	return rs, nil
}
