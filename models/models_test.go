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
	"sort"
	"testing"

	"github.com/k0kubun/pp"
)

func TestPackageInfoListUniqByName(t *testing.T) {
	var test = struct {
		in  PackageInfoList
		out PackageInfoList
	}{
		PackageInfoList{
			{
				Name: "hoge",
			},
			{
				Name: "fuga",
			},
			{
				Name: "hoge",
			},
		},
		PackageInfoList{
			{
				Name: "hoge",
			},
			{
				Name: "fuga",
			},
		},
	}

	actual := test.in.UniqByName()
	sort.Slice(actual, func(i, j int) bool {
		return actual[i].Name < actual[j].Name
	})
	sort.Slice(test.out, func(i, j int) bool {
		return test.out[i].Name < test.out[j].Name
	})
	for i, ePack := range test.out {
		if actual[i].Name != ePack.Name {
			t.Errorf("expected %#v, actual %#v", ePack.Name, actual[i].Name)
		}
	}
}

func TestMergeNewVersion(t *testing.T) {
	var test = struct {
		a        PackageInfoList
		b        PackageInfoList
		expected PackageInfoList
	}{
		PackageInfoList{
			{
				Name: "hoge",
			},
		},
		PackageInfoList{
			{
				Name:       "hoge",
				NewVersion: "1.0.0",
				NewRelease: "release1",
			},
		},
		PackageInfoList{
			{
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
