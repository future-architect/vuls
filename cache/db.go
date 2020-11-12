package cache

import (
	"time"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// DB has a cache instance
var DB Cache

const metabucket = "changelog-meta"

// Cache is a interface of cache
type Cache interface {
	Close() error
	GetMeta(string) (Meta, bool, error)
	RefreshMeta(Meta) error
	EnsureBuckets(Meta) error
	PrettyPrint(Meta) error
	GetChangelog(string, string) (string, error)
	PutChangelog(string, string, string) error
}

// Meta holds a server name, distro information of the scanned server and
// package information that was collected at the last scan.
type Meta struct {
	Name      string
	Distro    config.Distro
	Packs     models.Packages
	CreatedAt time.Time
}
