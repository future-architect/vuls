package models

import (
	"reflect"
	"testing"
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
		want map[string]Library
	}{
		{
			name: "single file",
			lss: LibraryScanners{
				{
					LockfilePath: "/pathA",
					Libs: []Library{
						{
							Name:    "libA",
							Version: "1.0.0",
						},
					},
				},
			},
			args: args{"/pathA", "libA"},
			want: map[string]Library{
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
					LockfilePath: "/pathA",
					Libs: []Library{
						{
							Name:    "libA",
							Version: "1.0.0",
						},
					},
				},
				{
					LockfilePath: "/pathB",
					Libs: []Library{
						{
							Name:    "libA",
							Version: "1.0.5",
						},
					},
				},
			},
			args: args{"/pathA", "libA"},
			want: map[string]Library{
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
					LockfilePath: "/pathA",
					Libs: []Library{
						{
							Name:    "libA",
							Version: "1.0.0",
						},
					},
				},
			},
			args: args{"/pathA", "libB"},
			want: map[string]Library{},
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
