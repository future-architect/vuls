/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
