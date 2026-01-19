package scanner

import (
	"reflect"
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/future-architect/vuls/models"
)

func Test_convertLibWithScanner(t *testing.T) {
	type args struct {
		apps                   []ftypes.Application
		includeDevDependencies bool
	}
	tests := []struct {
		name string
		args args
		want []models.LibraryScanner
	}{
		{
			name: "exclude dev dependencies",
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
				includeDevDependencies: false,
			},
			want: []models.LibraryScanner{
				{
					Type:         ftypes.Npm,
					LockfilePath: "package-lock.json",
					Libs: []models.Library{
						{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
						{Name: "express", Version: "4.18.0", PURL: "pkg:npm/express@4.18.0"},
					},
				},
			},
		},
		{
			name: "include dev dependencies",
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
				includeDevDependencies: true,
			},
			want: []models.LibraryScanner{
				{
					Type:         ftypes.Npm,
					LockfilePath: "package-lock.json",
					Libs: []models.Library{
						{Name: "lodash", Version: "4.17.21", PURL: "pkg:npm/lodash@4.17.21"},
						{Name: "jest", Version: "29.0.0", PURL: "pkg:npm/jest@29.0.0"},
						{Name: "express", Version: "4.18.0", PURL: "pkg:npm/express@4.18.0"},
					},
				},
			},
		},
		{
			name: "all dev dependencies excluded",
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
				includeDevDependencies: false,
			},
			want: []models.LibraryScanner{
				{
					Type:         ftypes.Npm,
					LockfilePath: "package-lock.json",
					Libs:         []models.Library{},
				},
			},
		},
		{
			name: "empty apps",
			args: args{
				apps:                   []ftypes.Application{},
				includeDevDependencies: false,
			},
			want: []models.LibraryScanner{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertLibWithScanner(tt.args.apps, tt.args.includeDevDependencies)
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
