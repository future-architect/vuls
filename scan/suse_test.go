/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package scan

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/k0kubun/pp"
)

func TestScanUpdatablePackages(t *testing.T) {
	r := newSUSE(config.ServerInfo{})
	r.Distro = config.Distro{Family: "sles"}
	stdout := `S | Repository                                  | Name                          | Current Version             | Available Version           | Arch
--+---------------------------------------------+-------------------------------+-----------------------------+-----------------------------+-------
v | SLES12-SP2-Updates                          | SUSEConnect                   | 0.3.0-19.8.1                | 0.3.1-19.11.2               | x86_64
v | SLES12-SP2-Updates                          | SuSEfirewall2                 | 3.6.312-2.3.1               | 3.6.312-2.10.1              | noarch`

	var tests = []struct {
		in  string
		out models.Packages
	}{
		{
			stdout,
			models.NewPackages(
				models.Package{
					Name:       "SUSEConnect",
					NewVersion: "0.3.1",
					NewRelease: "19.11.2",
					Arch:       "x86_64",
				},
				models.Package{
					Name:       "SuSEfirewall2",
					NewVersion: "3.6.312",
					NewRelease: "2.10.1",
					Arch:       "noarch",
				},
			),
		},
	}

	for _, tt := range tests {
		packages, err := r.parseZypperLULines(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
			return
		}
		for name, ePack := range tt.out {
			if !reflect.DeepEqual(ePack, packages[name]) {
				e := pp.Sprintf("%v", ePack)
				a := pp.Sprintf("%v", packages[name])
				t.Errorf("expected %s, actual %s", e, a)
			}
		}
	}
}

func TestScanUpdatablePackage(t *testing.T) {
	r := newSUSE(config.ServerInfo{})
	r.Distro = config.Distro{Family: "sles"}
	stdout := `v | SLES12-SP2-Updates                          | SUSEConnect                   | 0.3.0-19.8.1                | 0.3.1-19.11.2               | x86_64`

	var tests = []struct {
		in  string
		out models.Package
	}{
		{
			stdout,
			models.Package{
				Name:       "SUSEConnect",
				NewVersion: "0.3.1",
				NewRelease: "19.11.2",
				Arch:       "x86_64",
			},
		},
	}

	for _, tt := range tests {
		pack, err := r.parseZypperLUOneLine(tt.in)
		if err != nil {
			t.Errorf("Error has occurred, err: %s\ntt.in: %v", err, tt.in)
			return
		}
		if !reflect.DeepEqual(*pack, tt.out) {
			e := pp.Sprintf("%v", tt.out)
			a := pp.Sprintf("%v", pack)
			t.Errorf("expected %s, actual %s", e, a)
		}
	}
}
