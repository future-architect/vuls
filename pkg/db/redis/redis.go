package redis

import (
	"github.com/go-redis/redis/v9"
	"github.com/pkg/errors"

	"github.com/future-architect/vuls/pkg/db/types"
)

type options struct {
}

type Option interface {
	apply(*options)
}

type DB struct {
	conn *redis.Client
}

func Open(dbPath string, debug bool, opts ...Option) (*DB, error) {
	redisOpts, err := redis.ParseURL(dbPath)
	if err != nil {
		return nil, errors.Wrap(err, "parse redis URL")
	}
	return &DB{conn: redis.NewClient(redisOpts)}, nil
}

func (db *DB) Close() error {
	if db.conn == nil {
		return nil
	}
	if err := db.conn.Close(); err != nil {
		return errors.Wrap(err, "close redis")
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

func (db *DB) GetKBtoProduct(release string, kb []string) ([]string, error) {
	return nil, nil
}
