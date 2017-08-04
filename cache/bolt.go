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
	"encoding/json"
	"fmt"
	"time"

	"github.com/boltdb/bolt"
	"github.com/future-architect/vuls/util"
	"github.com/sirupsen/logrus"
)

// Bolt holds a pointer of bolt.DB
// boltdb is used to store a cache of Changelogs of Ubuntu/Debian
type Bolt struct {
	Path string
	Log  *logrus.Entry
	db   *bolt.DB
}

// SetupBolt opens a boltdb and creates a meta bucket if not exists.
func SetupBolt(path string, l *logrus.Entry) error {
	l.Infof("Open boltDB: %s", path)
	db, err := bolt.Open(path, 0600, nil)
	if err != nil {
		return err
	}

	b := Bolt{
		Path: path,
		Log:  l,
		db:   db,
	}
	if err = b.createBucketIfNotExists(metabucket); err != nil {
		return err
	}

	DB = b
	return nil
}

// Close a db.
func (b Bolt) Close() error {
	if b.db == nil {
		return nil
	}
	return b.db.Close()
}

//  CreateBucketIfNotExists creates a buket that is specified by arg.
func (b *Bolt) createBucketIfNotExists(name string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(name))
		if err != nil {
			return fmt.Errorf("Failed to create bucket: %s", err)
		}
		return nil
	})
}

// GetMeta gets a Meta Information os the servername to boltdb.
func (b Bolt) GetMeta(serverName string) (meta Meta, found bool, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(metabucket))
		v := bkt.Get([]byte(serverName))
		if len(v) == 0 {
			found = false
			return nil
		}
		if e := json.Unmarshal(v, &meta); e != nil {
			return e
		}
		found = true
		return nil
	})
	return
}

// RefreshMeta gets a Meta Information os the servername to boltdb.
func (b Bolt) RefreshMeta(meta Meta) error {
	meta.CreatedAt = time.Now()
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("Failed to marshal to JSON: %s", err)
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(metabucket))
		if err := bkt.Put([]byte(meta.Name), jsonBytes); err != nil {
			return err
		}
		b.Log.Debugf("Refreshed Meta: %s", meta.Name)
		return nil
	})
}

// EnsureBuckets puts a Meta information and create a buket that holds changelogs.
func (b Bolt) EnsureBuckets(meta Meta) error {
	jsonBytes, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("Failed to marshal to JSON: %s", err)
	}
	return b.db.Update(func(tx *bolt.Tx) error {
		b.Log.Debugf("Put to meta: %s", meta.Name)
		bkt := tx.Bucket([]byte(metabucket))
		if err := bkt.Put([]byte(meta.Name), jsonBytes); err != nil {
			return err
		}

		// re-create a bucket (bucket name: servername)
		bkt = tx.Bucket([]byte(meta.Name))
		if bkt != nil {
			b.Log.Debugf("Delete bucket: %s", meta.Name)
			if err := tx.DeleteBucket([]byte(meta.Name)); err != nil {
				return err
			}
			b.Log.Debugf("Bucket deleted: %s", meta.Name)
		}
		b.Log.Debugf("Create bucket: %s", meta.Name)
		if _, err := tx.CreateBucket([]byte(meta.Name)); err != nil {
			return err
		}
		b.Log.Debugf("Bucket created: %s", meta.Name)
		return nil
	})
}

// PrettyPrint is for debug
func (b Bolt) PrettyPrint(meta Meta) error {
	return b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(metabucket))
		v := bkt.Get([]byte(meta.Name))
		b.Log.Debugf("Meta: key:%s, value:%s", meta.Name, v)

		bkt = tx.Bucket([]byte(meta.Name))
		c := bkt.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			b.Log.Debugf("key:%s, len: %d, %s...",
				k, len(v), util.Truncate(string(v), 30))
		}
		return nil
	})
}

// GetChangelog get the changelgo of specified packName from the Bucket
func (b Bolt) GetChangelog(servername, packName string) (changelog string, err error) {
	err = b.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(servername))
		if bkt == nil {
			return fmt.Errorf("Faild to get Bucket: %s", servername)
		}
		v := bkt.Get([]byte(packName))
		if v == nil {
			changelog = ""
			return nil
		}
		changelog = string(v)
		return nil
	})
	return
}

// PutChangelog put the changelgo of specified packName into the Bucket
func (b Bolt) PutChangelog(servername, packName, changelog string) error {
	return b.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(servername))
		if bkt == nil {
			return fmt.Errorf("Faild to get Bucket: %s", servername)
		}
		if err := bkt.Put([]byte(packName), []byte(changelog)); err != nil {
			return err
		}
		return nil
	})
}
