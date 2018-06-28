package gost

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
	gostmodels "github.com/knqyf263/gost/models"
)

func TestStorePackageStatueses(t *testing.T) {
	var tests = []struct {
		pkgstats  []gostmodels.RedhatPackageState
		installed models.Packages
		release   string
		in        models.VulnInfo
		out       models.VulnInfo
	}{

		// one
		{
			pkgstats: []gostmodels.RedhatPackageState{
				{
					FixState:    "Will not fix",
					PackageName: "bouncycastle",
					Cpe:         "cpe:/o:redhat:enterprise_linux:7",
				},
			},
			installed: models.Packages{
				"bouncycastle": models.Package{},
			},
			release: "7",
			in:      models.VulnInfo{},
			out: models.VulnInfo{
				AffectedPackages: []models.PackageStatus{
					{
						Name:        "bouncycastle",
						FixState:    "Will not fix",
						NotFixedYet: true,
					},
				},
			},
		},

		// two
		{
			pkgstats: []gostmodels.RedhatPackageState{
				{
					FixState:    "Will not fix",
					PackageName: "bouncycastle",
					Cpe:         "cpe:/o:redhat:enterprise_linux:7",
				},
				{
					FixState:    "Fix deferred",
					PackageName: "pack_a",
					Cpe:         "cpe:/o:redhat:enterprise_linux:7",
				},
				// ignore not-installed-package
				{
					FixState:    "Fix deferred",
					PackageName: "pack_b",
					Cpe:         "cpe:/o:redhat:enterprise_linux:7",
				},
			},
			installed: models.Packages{
				"bouncycastle": models.Package{},
				"pack_a":       models.Package{},
			},
			release: "7",
			in:      models.VulnInfo{},
			out: models.VulnInfo{
				AffectedPackages: []models.PackageStatus{
					{
						Name:        "bouncycastle",
						FixState:    "Will not fix",
						NotFixedYet: true,
					},
					{
						Name:        "pack_a",
						FixState:    "Fix deferred",
						NotFixedYet: true,
					},
				},
			},
		},

		// ignore affected
		{
			pkgstats: []gostmodels.RedhatPackageState{
				{
					FixState:    "affected",
					PackageName: "bouncycastle",
					Cpe:         "cpe:/o:redhat:enterprise_linux:7",
				},
			},
			installed: models.Packages{
				"bouncycastle": models.Package{},
			},
			release: "7",
			in:      models.VulnInfo{},
			out:     models.VulnInfo{},
		},

		// look only the same os release.
		{
			pkgstats: []gostmodels.RedhatPackageState{
				{
					FixState:    "Will not fix",
					PackageName: "bouncycastle",
					Cpe:         "cpe:/o:redhat:enterprise_linux:6",
				},
			},
			installed: models.Packages{
				"bouncycastle": models.Package{},
			},
			release: "7",
			in:      models.VulnInfo{},
			out:     models.VulnInfo{},
		},
	}

	r := RedHat{}
	for i, tt := range tests {
		out := r.setPackageStates(&tt.in, tt.pkgstats, tt.installed, tt.release)
		if ok := reflect.DeepEqual(tt.out, *out); !ok {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, *out)
		}
	}
}
