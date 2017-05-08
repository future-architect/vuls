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

package models

import (
	"reflect"
	"testing"

	"github.com/k0kubun/pp"
)

func TestMergeNewVersion(t *testing.T) {
	var test = struct {
		a        Packages
		b        Packages
		expected Packages
	}{
		Packages{
			"hoge": {
				Name: "hoge",
			},
		},
		Packages{
			"hoge": {
				Name:       "hoge",
				NewVersion: "1.0.0",
				NewRelease: "release1",
			},
		},
		Packages{
			"hoge": {
				Name:       "hoge",
				NewVersion: "1.0.0",
				NewRelease: "release1",
			},
		},
	}

	test.a.MergeNewVersion(test.b)
	if !reflect.DeepEqual(test.a, test.expected) {
		e := pp.Sprintf("%v", test.a)
		a := pp.Sprintf("%v", test.expected)
		t.Errorf("expected %s, actual %s", e, a)
	}
}
func TestVulnInfosSetGet(t *testing.T) {
	var test = struct {
		in  []string
		out []string
	}{
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
			"CVE1",
			"CVE1",
			"CVE2",
			"CVE3",
		},
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
		},
	}

	//  var ps packageCveInfos
	var ps VulnInfos
	for _, cid := range test.in {
		ps.Upsert(VulnInfo{CveID: cid})
	}

	if len(test.out) != len(ps) {
		t.Errorf("length: expected %d, actual %d", len(test.out), len(ps))
	}

	for i, expectedCid := range test.out {
		if expectedCid != ps[i].CveID {
			t.Errorf("expected %s, actual %s", expectedCid, ps[i].CveID)
		}
	}
	for _, cid := range test.in {
		p, _ := ps.Get(cid)
		if p.CveID != cid {
			t.Errorf("expected %s, actual %s", cid, p.CveID)
		}
	}
}
