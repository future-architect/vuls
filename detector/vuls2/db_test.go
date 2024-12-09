package vuls2

import (
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/MaineK00n/vuls2/pkg/db/common"
	"github.com/MaineK00n/vuls2/pkg/db/common/types"
	"github.com/future-architect/vuls/config"
)

func Test_isStale(t *testing.T) {
	type args struct {
		vuls2Cnf config.Vuls2DictConf
		now      time.Time
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
				vuls2Cnf: config.Vuls2DictConf{},
				now:      *parse("2024-01-02T00:00:00Z"),
			},
			want: true,
		},
		{
			name: "just created",
			args: args{
				vuls2Cnf: config.Vuls2DictConf{},
				now:      *parse("2024-01-02T00:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: common.SchemaVersion,
			},
			want: false,
		},
		{
			name: "8 hours old",
			args: args{
				vuls2Cnf: config.Vuls2DictConf{},
				now:      *parse("2024-01-02T08:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T00:00:00Z"),
				SchemaVersion: common.SchemaVersion,
			},
			want: true,
		},
		{
			name: "8 hours old, but download recently",
			args: args{
				vuls2Cnf: config.Vuls2DictConf{},
				now:      *parse("2024-01-02T08:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T07:30:00Z"),
				SchemaVersion: common.SchemaVersion,
			},
			want: false,
		},
		{
			name: "wrong schema version",
			args: args{
				vuls2Cnf: config.Vuls2DictConf{},
				now:      *parse("2024-01-02T08:00:00Z"),
			},
			metadata: &types.Metadata{
				LastModified:  *parse("2024-01-02T00:00:00Z"),
				Downloaded:    parse("2024-01-02T07:30:00Z"),
				SchemaVersion: common.SchemaVersion + 42,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := t.TempDir()
			tt.args.vuls2Cnf.Path = filepath.Join(d, "vuls.db")
			if tt.metadata != nil {
				if err := putMetadata(t, *tt.metadata, tt.args.vuls2Cnf.Path); err != nil {
					t.Errorf("putMetadata() err = %v", err)
					return
				}
			}
			got, err := isStale(tt.args.vuls2Cnf, tt.args.now)
			if (err != nil) != tt.wantErr {
				t.Errorf("isStale() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("isStale() = %v, want %v", got, tt.want)
			}
		})
	}

}

func putMetadata(t *testing.T, metadata types.Metadata, path string) error {
	c := common.Config{
		Type: "boltdb",
		Path: path,
	}
	dbc, err := c.New()
	if err != nil {
		t.Errorf("c.New() err = %v", err)
		return err
	}
	if err := dbc.Open(); err != nil {
		t.Errorf("dbc.Open() err = %v", err)
		return err
	}
	defer dbc.Close()
	if err := dbc.Initialize(); err != nil {
		t.Errorf("dbc.Initialize() err = %v", err)
		return err
	}
	if err := dbc.PutMetadata(metadata); err != nil {
		t.Errorf("dbc.PutMetadata() err = %v", err)
		return err
	}
	return nil
}

func parse(date string) *time.Time {
	t, _ := time.Parse(time.RFC3339, date)
	return &t
}
