package rdb

import (
	"database/sql"

	"github.com/pkg/errors"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	_ "modernc.org/sqlite"

	"github.com/future-architect/vuls/pkg/db/types"
)

type options struct {
}

type Option interface {
	apply(*options)
}

type DB struct {
	conn *gorm.DB
}

func Open(dbType, dbPath string, debug bool, opts ...Option) (*DB, error) {
	switch dbType {
	case "sqlite3":
		// db, err := gorm.Open(sqlite.Open(dbPath))
		db := &gorm.DB{}
		conn, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return nil, errors.Wrap(err, "open sqlite3")
		}
		db.ConnPool = conn
		return &DB{conn: db}, nil
	case "mysql":
		db, err := gorm.Open(mysql.Open(dbPath))
		if err != nil {
			return nil, errors.Wrap(err, "open mysql")
		}
		return &DB{conn: db}, nil
	case "postgres":
		db, err := gorm.Open(postgres.Open(dbPath))
		if err != nil {
			return nil, errors.Wrap(err, "open postgres")
		}
		return &DB{conn: db}, nil
	default:
		return nil, errors.Errorf(`unexpected dbType. accepts: ["sqlite3", "mysql", "postgres"], received: "%s"`, dbType)
	}
}

func (db *DB) Close() error {
	if db.conn == nil {
		return nil
	}

	var (
		sqlDB *sql.DB
		err   error
	)
	if sqlDB, err = db.conn.DB(); err != nil {
		return errors.Wrap(err, "get *sql.DB")
	}
	if err := sqlDB.Close(); err != nil {
		return errors.Wrap(err, "close *sql.DB")
	}
	return nil
}

func (db *DB) PutVulnerability(src, key string, value types.Vulnerability) error {
	return nil
}

func (db *DB) PutPackage(src, key string, value map[string]types.Packages) error {
	return nil
}

func (db *DB) PutCPEConfiguration(src, key string, value map[string]types.CPEConfigurations) error {
	return nil
}

func (db *DB) PutRedHatRepoToCPE(src, key string, value types.RepositoryToCPE) error {
	return nil
}

func (db *DB) PutWindowsSupercedence(src, key string, value types.Supercedence) error {
	return nil
}

func (db *DB) GetVulnerability(ids []string) (map[string]map[string]types.Vulnerability, error) {
	return nil, nil
}

func (db *DB) GetPackage(family, release string, name string) (map[string]map[string]map[string]types.Package, error) {
	return nil, nil
}

func (db *DB) GetCPEConfiguration(partvendorproduct string) (map[string]map[string]map[string][]types.CPEConfiguration, error) {
	return nil, nil
}

func (db *DB) GetSupercedence(kb []string) (map[string][]string, error) {
	return nil, nil
}

func (db *DB) GetKBtoProduct(elease string, kb []string) ([]string, error) {
	return nil, nil
}
