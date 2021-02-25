// +build !scanner

package oval

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

func TestPackNamesOfUpdateDebian(t *testing.T) {
	var tests = []struct {
		in       models.ScanResult
		defPacks defPacks
		out      models.ScanResult
	}{
		{
			in: models.ScanResult{
				ScannedCves: models.VulnInfos{
					"CVE-2000-1000": models.VulnInfo{
						AffectedPackages: models.PackageFixStatuses{
							{Name: "packA"},
							{Name: "packC"},
						},
					},
				},
			},
			defPacks: defPacks{
				def: ovalmodels.Definition{
					Debian: ovalmodels.Debian{
						CveID: "CVE-2000-1000",
					},
				},
				binpkgFixstat: map[string]fixStat{
					"packB": {
						notFixedYet: true,
						fixedIn:     "1.0.0",
					},
				},
			},
			out: models.ScanResult{
				ScannedCves: models.VulnInfos{
					"CVE-2000-1000": models.VulnInfo{
						AffectedPackages: models.PackageFixStatuses{
							{Name: "packA"},
							{Name: "packB", NotFixedYet: true, FixedIn: "1.0.0"},
							{Name: "packC"},
						},
					},
				},
			},
		},
	}

	// util.Log = util.NewCustomLogger()
	for i, tt := range tests {
		Debian{}.update(&tt.in, tt.defPacks)
		e := tt.out.ScannedCves["CVE-2000-1000"].AffectedPackages
		a := tt.in.ScannedCves["CVE-2000-1000"].AffectedPackages
		if !reflect.DeepEqual(a, e) {
			t.Errorf("[%d] expected: %#v\n  actual: %#v\n", i, e, a)
		}
	}
}
