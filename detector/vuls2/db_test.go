package vuls2_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/xerrors"

	"github.com/MaineK00n/vuls2/pkg/db/fetch"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/detector/vuls2"
)

func Test_shouldDownload(t *testing.T) {
	type args struct {
		vuls2Conf config.Vuls2Conf
		now       time.Time
	}
	tests := []struct {
		name     string
		args     args
		metadata *types.Metadata
		want     bool
		wantErr  bool
	}{
		{
			name: "no db file",
			args: args{
				vuls2Conf: config.Vuls2Conf{},
				now:       *parse("2024-01-02T00:00:00Z"),
			},
			want: true,
		},
		{
			name: "no db file, but skip update",
			args: args{
				vuls2Conf: config.Vuls2Conf{
					SkipUpdate: true,
				},
				now: *parse("2024-01-02T00:00:00Z"),
			},
			wantErr: true,
		},
		{
			name: "just created",
			args: args{
				vuls2Conf: config.Vuls2Conf{},
				now:       *parse("2024-01-02T00:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: schemaVersionBoltDB(t),
			},
			want: false,
		},
		{
			name: "8 hours old",
			args: args{
				vuls2Conf: config.Vuls2Conf{},
				now:       *parse("2024-01-02T08:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: schemaVersionBoltDB(t),
			},
			want: true,
		},
		{
			name: "8 hours old, but skip update",
			args: args{
				vuls2Conf: config.Vuls2Conf{
					SkipUpdate: true,
				},
				now: *parse("2024-01-02T08:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: schemaVersionBoltDB(t),
			},
			want: false,
		},
		{
			name: "8 hours old, but download recently",
			args: args{
				vuls2Conf: config.Vuls2Conf{},
				now:       *parse("2024-01-02T08:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T07:30:00Z"),
				SchemaVersion: schemaVersionBoltDB(t),
			},
			want: false,
		},
		{
			name: "schema version mismatch",
			args: args{
				vuls2Conf: config.Vuls2Conf{},
				now:       *parse("2024-01-02T00:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: schemaVersionBoltDB(t) + 1,
			},
			want: true,
		},
		{
			name: "schema version mismatch, but skip update",
			args: args{
				vuls2Conf: config.Vuls2Conf{
					SkipUpdate: true,
				},
				now: *parse("2024-01-02T00:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: schemaVersionBoltDB(t) + 1,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			tt.args.vuls2Conf.Path = filepath.Join(d, "vuls.db")
			if tt.metadata != nil {
				if err := putMetadata(*tt.metadata, tt.args.vuls2Conf.Path); err != nil {
					t.Errorf("putMetadata err = %v", err)
					return
				}
			}
			got, err := vuls2.ShouldDownload(tt.args.vuls2Conf, tt.args.now)
			if (err != nil) != tt.wantErr {
				t.Errorf("shouldDownload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("shouldDownload() = %v, want %v", got, tt.want)
			}
		})
	}

}

func Test_newDBConfig_removesOldDBBeforeFetch(t *testing.T) {
	d := t.TempDir()
	path := filepath.Join(d, "vuls.db")

	// Pre-create a stale db so that shouldDownload returns true (willDownload).
	// Use a time relative to now since newDBConfig compares against time.Now().
	stale := time.Now().Add(-8 * time.Hour)
	if err := putMetadata(types.Metadata{
		LastModified:  stale,
		Downloaded:    &stale,
		SchemaVersion: schemaVersionBoltDB(t),
	}, path); err != nil {
		t.Fatalf("putMetadata (old db) err = %v", err)
	}

	var called, removedBeforeFetch bool
	restore := vuls2.SetFetchDB(func(_ ...fetch.Option) error {
		called = true
		// The old db must already be gone by the time fetch runs.
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			removedBeforeFetch = true
		}
		// Simulate a successful fetch by writing a fresh, valid db at the path.
		fresh := time.Now()
		return putMetadata(types.Metadata{
			LastModified:  fresh,
			Downloaded:    &fresh,
			SchemaVersion: schemaVersionBoltDB(t),
		}, path)
	})
	defer restore()

	if _, err := vuls2.NewDBConfig(config.Vuls2Conf{Path: path}, true); err != nil {
		t.Fatalf("NewDBConfig() err = %v", err)
	}
	if !called {
		t.Fatal("fetchDB was not called")
	}
	if !removedBeforeFetch {
		t.Error("old db was not removed before fetch")
	}
}

func putMetadata(metadata types.Metadata, path string) error {
	c := session.Config{
		Type: "boltdb",
		Path: path,
	}
	sesh, err := c.New()
	if err != nil {
		return xerrors.Errorf("c.New(). err: %w", err)
	}
	if err := sesh.Storage().Open(); err != nil {
		return xerrors.Errorf("sesh.Storage().Open(). err: %w", err)
	}
	defer sesh.Storage().Close()
	if err := sesh.Storage().Initialize(); err != nil {
		return xerrors.Errorf("sesh.Storage().Initialize(). err: %w", err)
	}
	if err := sesh.Storage().PutMetadata(metadata); err != nil {
		return xerrors.Errorf("sesh.Storage().PutMetadata(). err: %w", err)
	}
	return nil
}

func parse(date string) *time.Time {
	t, _ := time.Parse(time.RFC3339, date)
	return &t
}

func schemaVersionBoltDB(t *testing.T) uint {
	sv, err := session.SchemaVersion("boltdb")
	if err != nil {
		t.Fatalf("session.SchemaVersion() err: %v", err)
	}
	return sv
}
