package models

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
)

func TestScan(t *testing.T) {
	var tests = []struct {
		path string
		pkgs []types.Library
	}{
		{
			path: "app/package-lock.json",
			pkgs: []types.Library{
				{
					Name:    "jquery",
					Version: "2.2.4",
				},
				{
					Name:    "@babel/traverse",
					Version: "7.4.4",
				},
			},
		},
	}

	if err := log.InitLogger(false, false); err != nil {
		t.Errorf("trivy logger failed")
	}

	cacheDir := utils.DefaultCacheDir()
	if err := db.Init(cacheDir); err != nil {
		t.Errorf("trivy db.Init failed")
	}
	for _, v := range tests {
		lib := LibraryScanner{
			Path: v.path,
			Libs: v.pkgs,
		}
		actual, err := lib.Scan()
		if err != nil {
			t.Errorf("error occurred")
		}
		if len(actual) == 0 {
			t.Errorf("no vuln found : actual: %v\n", actual)
		}
	}
	db.Close()
}

func TestLibraryScanners_Find(t *testing.T) {
	type args struct {
		name string
	}
	tests := []struct {
		name string
		lss  LibraryScanners
		args args
		want map[string]types.Library
	}{
		{
			name: "single file",
			lss: LibraryScanners{
				{
					Path: "/pathA",
					Libs: []types.Library{
						{
							Name:    "libA",
							Version: "1.0.0",
						},
					},
				},
			},
			args: args{"libA"},
			want: map[string]types.Library{
				"/pathA": {
					Name:    "libA",
					Version: "1.0.0",
				},
			},
		},
		{
			name: "multi file",
			lss: LibraryScanners{
				{
					Path: "/pathA",
					Libs: []types.Library{
						{
							Name:    "libA",
							Version: "1.0.0",
						},
					},
				},
				{
					Path: "/pathB",
					Libs: []types.Library{
						{
							Name:    "libA",
							Version: "1.0.5",
						},
					},
				},
			},
			args: args{"libA"},
			want: map[string]types.Library{
				"/pathA": {
					Name:    "libA",
					Version: "1.0.0",
				},
				"/pathB": {
					Name:    "libA",
					Version: "1.0.5",
				},
			},
		},
		{
			name: "miss",
			lss: LibraryScanners{
				{
					Path: "/pathA",
					Libs: []types.Library{
						{
							Name:    "libA",
							Version: "1.0.0",
						},
					},
				},
			},
			args: args{"libB"},
			want: map[string]types.Library{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.lss.Find(tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryScanners.Find() = %v, want %v", got, tt.want)
			}
		})
	}
}
