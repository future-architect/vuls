/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
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
						AffectedPackages: models.PackageStatuses{{Name: "packA"}},
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
						AffectedPackages: models.PackageStatuses{
							{Name: "packA"},
							{Name: "packB"},
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
