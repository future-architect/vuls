package pkg

import (
	"testing"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestConvert_DevDependency(t *testing.T) {
	tests := []struct {
		name     string
		results  types.Results
		wantLibs map[string]bool // key: name+version, value: expected Dev
	}{
		{
			name: "with dev dependencies",
			results: types.Results{
				{
					Target: "package-lock.json",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Npm,
					Packages: []ftypes.Package{
						{
							Name:    "lodash",
							Version: "4.17.21",
							Dev:     false,
						},
						{
							Name:    "jest",
							Version: "29.0.0",
							Dev:     true,
						},
						{
							Name:    "mocha",
							Version: "10.0.0",
							Dev:     true,
						},
					},
				},
			},
			wantLibs: map[string]bool{
				"lodash4.17.21": false,
				"jest29.0.0":    true,
				"mocha10.0.0":   true,
			},
		},
		{
			name: "all production dependencies",
			results: types.Results{
				{
					Target: "package-lock.json",
					Class:  types.ClassLangPkg,
					Type:   ftypes.Npm,
					Packages: []ftypes.Package{
						{
							Name:    "express",
							Version: "4.18.0",
							Dev:     false,
						},
						{
							Name:    "axios",
							Version: "1.0.0",
							Dev:     false,
						},
					},
				},
			},
			wantLibs: map[string]bool{
				"express4.18.0": false,
				"axios1.0.0":    false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Convert(tt.results)
			if err != nil {
				t.Fatalf("Convert() error = %v", err)
			}

			// Check library scanners
			for _, ls := range got.LibraryScanners {
				for _, lib := range ls.Libs {
					key := lib.Name + lib.Version
					wantDev, ok := tt.wantLibs[key]
					if !ok {
						continue
					}
					if lib.Dev != wantDev {
						t.Errorf("Library %s: Dev = %v, want %v", lib.Name, lib.Dev, wantDev)
					}
				}
			}
		})
	}
}
