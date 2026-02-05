package scanner

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/future-architect/vuls/models"
)

func Test_convertLibWithScanner(t *testing.T) {
	type args struct {
		apps []ftypes.Application
	}
	tests := []struct {
		name string
		args args
		want []models.LibraryScanner
	}{
		{
			name: "includes all dependencies with dev flag preserved",
			args: args{
				apps: []ftypes.Application{
					{
						Type:     ftypes.Npm,
						FilePath: "package-lock.json",
						Packages: []ftypes.Package{
							{Name: "lodash", Version: "4.17.21", Dev: false},
							{Name: "jest", Version: "29.0.0", Dev: true},
							{Name: "express", Version: "4.18.0", Dev: false},
						},
					},
				},
			},
			want: []models.LibraryScanner{
				{
					Type:         ftypes.Npm,
					LockfilePath: "package-lock.json",
					Libs: []models.Library{
						{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21", Dev: false},
						{Name: "jest", Version: "29.0.0", PURL: "pkg:npm/jest@29.0.0", Dev: true},
						{Name: "express", Version: "4.18.0", PURL: "pkg:npm/express@4.18.0", Dev: false},
					},
				},
			},
		},
		{
			name: "all dev dependencies are included",
			args: args{
				apps: []ftypes.Application{
					{
						Type:     ftypes.Npm,
						FilePath: "package-lock.json",
						Packages: []ftypes.Package{
							{Name: "jest", Version: "29.0.0", Dev: true},
							{Name: "mocha", Version: "10.0.0", Dev: true},
						},
					},
				},
			},
			want: []models.LibraryScanner{
				{
					Type:         ftypes.Npm,
					LockfilePath: "package-lock.json",
					Libs: []models.Library{
						{Name: "jest", Version: "29.0.0", PURL: "pkg:npm/jest@29.0.0", Dev: true},
						{Name: "mocha", Version: "10.0.0", PURL: "pkg:npm/mocha@10.0.0", Dev: true},
					},
				},
			},
		},
		{
			name: "empty apps",
			args: args{
				apps: []ftypes.Application{},
			},
			want: []models.LibraryScanner{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertLibWithScanner(tt.args.apps)
			if err != nil {
				t.Errorf("convertLibWithScanner() error = %v", err)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertLibWithScanner() = %v, want %v", got, tt.want)
			}
		})
	}
}
