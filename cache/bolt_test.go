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
	"os"
	"reflect"
	"testing"

	"github.com/boltdb/bolt"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/sirupsen/logrus"
)

const path = "/tmp/vuls-test-cache-11111111.db"
const servername = "server1"

var meta = Meta{
	Name: servername,
	Distro: config.Distro{
		Family:  "ubuntu",
		Release: "16.04",
	},
	Packs: models.Packages{
		"apt": {
			Name:    "apt",
			Version: "1",
		},
	},
}

func TestSetupBolt(t *testing.T) {
	log := logrus.NewEntry(&logrus.Logger{})
	err := SetupBolt(path, log)
	if err != nil {
		t.Errorf("Failed to setup bolt: %s", err)
	}
	defer os.Remove(path)

	if err := DB.Close(); err != nil {
		t.Errorf("Failed to close bolt: %s", err)
	}

	// check if meta bucket exists
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Errorf("Failed to open bolt: %s", err)
	}

	db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(metabucket))
		if bkt == nil {
			t.Errorf("Meta bucket nof found")
		}
		return nil
	})

}

func TestEnsureBuckets(t *testing.T) {
	log := logrus.NewEntry(&logrus.Logger{})
	if err := SetupBolt(path, log); err != nil {
		t.Errorf("Failed to setup bolt: %s", err)
	}
	if err := DB.EnsureBuckets(meta); err != nil {
		t.Errorf("Failed to ensure buckets: %s", err)
	}
	defer os.Remove(path)

	m, found, err := DB.GetMeta(servername)
	if err != nil {
		t.Errorf("Failed to get meta: %s", err)
	}
	if !found {
		t.Errorf("Not Found in meta")
	}
	if meta.Name != m.Name || meta.Distro != m.Distro {
		t.Errorf("expected %v, actual %v", meta, m)
	}
	if !reflect.DeepEqual(meta.Packs, m.Packs) {
		t.Errorf("expected %v, actual %v", meta.Packs, m.Packs)
	}
	if err := DB.Close(); err != nil {
		t.Errorf("Failed to close bolt: %s", err)
	}

	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		t.Errorf("Failed to open bolt: %s", err)
	}
	db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(servername))
		if bkt == nil {
			t.Errorf("Meta bucket nof found")
		}
		return nil
	})
}

func TestPutGetChangelog(t *testing.T) {
	clog := "changelog-text"
	log := logrus.NewEntry(&logrus.Logger{})
	if err := SetupBolt(path, log); err != nil {
		t.Errorf("Failed to setup bolt: %s", err)
	}
	defer os.Remove(path)

	if err := DB.EnsureBuckets(meta); err != nil {
		t.Errorf("Failed to ensure buckets: %s", err)
	}
	if err := DB.PutChangelog(servername, "apt", clog); err != nil {
		t.Errorf("Failed to put changelog: %s", err)
	}
	if actual, err := DB.GetChangelog(servername, "apt"); err != nil {
		t.Errorf("Failed to get changelog: %s", err)
	} else {
		if actual != clog {
			t.Errorf("changelog is not same. e: %s, a: %s", clog, actual)
		}
	}
}
