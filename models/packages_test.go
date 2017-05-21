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

func TestMerge(t *testing.T) {
	var test = struct {
		a        Packages
		b        Packages
		expected Packages
	}{
		Packages{
			"hoge": {Name: "hoge"},
			"fuga": {Name: "fuga"},
		},
		Packages{
			"hega": {Name: "hega"},
			"hage": {Name: "hage"},
		},
		Packages{
			"hoge": {Name: "hoge"},
			"fuga": {Name: "fuga"},
			"hega": {Name: "hega"},
			"hage": {Name: "hage"},
		},
	}

	actual := test.a.Merge(test.b)
	if !reflect.DeepEqual(actual, test.expected) {
		e := pp.Sprintf("%v", test.expected)
		a := pp.Sprintf("%v", actual)
		t.Errorf("expected %s, actual %s", e, a)
	}
}

func TestFormatVersionsFromTo(t *testing.T) {
	var tests = []struct {
		packs    Packages
		expected string
	}{
		{
			packs: Packages{
				"hoge": {
					Name:       "hoge",
					Version:    "1.0.0",
					Release:    "release1",
					NewVersion: "1.0.1",
					NewRelease: "release2",
				},
			},
			expected: "hoge-1.0.0-release1 -> hoge-1.0.1-release2",
		},
		{
			packs: Packages{
				"hoge": {
					Name:       "hoge",
					Version:    "1.0.0",
					Release:    "",
					NewVersion: "1.0.1",
					NewRelease: "",
				},
			},
			expected: "hoge-1.0.0 -> hoge-1.0.1",
		},
		{
			packs: Packages{
				"hoge": {
					Name:       "hoge",
					Version:    "1.0.0",
					Release:    "",
					NewVersion: "1.0.1",
					NewRelease: "",
				},
				"fuga": {
					Name:       "fuga",
					Version:    "2.0.0",
					Release:    "",
					NewVersion: "2.0.1",
					NewRelease: "",
				},
			},
			expected: "hoge-1.0.0 -> hoge-1.0.1\nfuga-2.0.0 -> fuga-2.0.1",
		},
	}

	for _, tt := range tests {
		actual := tt.packs.FormatVersionsFromTo()
		if !reflect.DeepEqual(tt.expected, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", tt.expected, actual)
		}
	}
}
