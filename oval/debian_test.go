package oval

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
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
				actuallyAffectedPackNames: map[string]bool{
					"packB": true,
				},
			},
			out: models.ScanResult{
				ScannedCves: models.VulnInfos{
					"CVE-2000-1000": models.VulnInfo{
						AffectedPackages: models.PackageFixStatuses{
							{Name: "packA"},
							{Name: "packB", NotFixedYet: true},
							{Name: "packC"},
						},
					},
				},
			},
		},
	}

	util.Log = util.NewCustomLogger(config.ServerInfo{})
	for i, tt := range tests {
		Debian{}.update(&tt.in, tt.defPacks)
		e := tt.out.ScannedCves["CVE-2000-1000"].AffectedPackages
		a := tt.in.ScannedCves["CVE-2000-1000"].AffectedPackages
		if !reflect.DeepEqual(a, e) {
			t.Errorf("[%d] expected: %v\n  actual: %v\n", i, e, a)
		}
	}
}
