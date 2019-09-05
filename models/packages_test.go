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

func TestAddBinaryName(t *testing.T) {
	var tests = []struct {
		in       SrcPackage
		name     string
		expected SrcPackage
	}{
		{
			SrcPackage{Name: "hoge"},
			"curl",
			SrcPackage{
				Name:        "hoge",
				BinaryNames: []string{"curl"},
			},
		},
		{
			SrcPackage{
				Name:        "hoge",
				BinaryNames: []string{"curl"},
			},
			"curl",
			SrcPackage{
				Name:        "hoge",
				BinaryNames: []string{"curl"},
			},
		},
		{
			SrcPackage{
				Name:        "hoge",
				BinaryNames: []string{"curl"},
			},
			"openssh",
			SrcPackage{
				Name:        "hoge",
				BinaryNames: []string{"curl", "openssh"},
			},
		},
	}

	for _, tt := range tests {
		tt.in.AddBinaryName(tt.name)
		if !reflect.DeepEqual(tt.in, tt.expected) {
			t.Errorf("expected %#v, actual %#v", tt.in, tt.expected)
		}
	}
}

func TestFindByBinName(t *testing.T) {
	var tests = []struct {
		in       SrcPackages
		name     string
		expected *SrcPackage
		ok       bool
	}{
		{
			in: map[string]SrcPackage{
				"packA": {
					Name:        "srcA",
					BinaryNames: []string{"binA"},
					Version:     "1.0.0",
				},
				"packB": {
					Name:        "srcB",
					BinaryNames: []string{"binB"},
					Version:     "2.0.0",
				},
			},
			name: "binA",
			expected: &SrcPackage{
				Name:        "srcA",
				BinaryNames: []string{"binA"},
				Version:     "1.0.0",
			},
			ok: true,
		},
		{
			in: map[string]SrcPackage{
				"packA": {
					Name:        "srcA",
					BinaryNames: []string{"binA"},
					Version:     "1.0.0",
				},
				"packB": {
					Name:        "srcB",
					BinaryNames: []string{"binB"},
					Version:     "2.0.0",
				},
			},
			name:     "nobin",
			expected: nil,
			ok:       false,
		},
	}

	for i, tt := range tests {
		act, ok := tt.in.FindByBinName(tt.name)
		if ok != tt.ok {
			t.Errorf("[%d] expected %#v, actual %#v", i, tt.in, tt.expected)
		}
		if act != nil && !reflect.DeepEqual(*tt.expected, *act) {
			t.Errorf("[%d] expected %#v, actual %#v", i, tt.in, tt.expected)
		}
	}
}
