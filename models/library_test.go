package models

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
)

func TestLibraryScanners_Find(t *testing.T) {
	type args struct {
		path string
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
			args: args{"/pathA", "libA"},
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
			args: args{"/pathA", "libA"},
			want: map[string]types.Library{
				"/pathA": {
					Name:    "libA",
					Version: "1.0.0",
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
			args: args{"/pathA", "libB"},
			want: map[string]types.Library{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.lss.Find(tt.args.path, tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryScanners.Find() = %v, want %v", got, tt.want)
			}
		})
	}
}
