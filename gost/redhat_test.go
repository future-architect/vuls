//go:build !scanner
// +build !scanner

package gost

import (
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/models"
	gostmodels "github.com/vulsio/gost/models"
)

func TestParseCwe(t *testing.T) {
	var tests = []struct {
		in  string
		out []string
	}{
		{
			in:  "CWE-665->(CWE-200|CWE-89)",
			out: []string{"CWE-665", "CWE-200", "CWE-89"},
		},
		{
			in:  "CWE-841->CWE-770->CWE-454",
			out: []string{"CWE-841", "CWE-770", "CWE-454"},
		},
		{
			in:  "(CWE-122|CWE-125)",
			out: []string{"CWE-122", "CWE-125"},
		},
	}

	r := RedHat{}
	for i, tt := range tests {
		out := r.parseCwe(tt.in)
		sort.Strings(out)
		sort.Strings(tt.out)
		if !reflect.DeepEqual(tt.out, out) {
			t.Errorf("[%d]expected: %s, actual: %s", i, tt.out, out)
		}
	}
}

func TestRedHat_mergePackageStates(t *testing.T) {
	type args struct {
		ps        []gostmodels.RedhatPackageState
		installed models.Packages
		release   string
	}
	tests := []struct {
		name string
		args args
		want models.PackageFixStatuses
	}{
		{
			name: "affected",
			args: args{
				ps: []gostmodels.RedhatPackageState{
					{
						FixState:    "New",
						PackageName: "pkg1",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
					{
						FixState:    "Under investigation",
						PackageName: "pkg2",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
					{
						FixState:    "Affected",
						PackageName: "pkg3",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
					{
						FixState:    "Fix deferred",
						PackageName: "pkg4",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
					{
						FixState:    "Will not fix",
						PackageName: "pkg5",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
					{
						FixState:    "Out of support scope",
						PackageName: "pkg6",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
				},
				installed: models.Packages{"pkg1": models.Package{}, "pkg2": models.Package{}, "pkg3": models.Package{}, "pkg4": models.Package{}, "pkg5": models.Package{}, "pkg6": models.Package{}},
				release:   "8.1",
			},
			want: models.PackageFixStatuses{
				{
					Name:        "pkg3",
					FixState:    "Affected",
					NotFixedYet: true,
				},
				{
					Name:        "pkg4",
					FixState:    "Fix deferred",
					NotFixedYet: true,
				},
				{
					Name:        "pkg5",
					FixState:    "Will not fix",
					NotFixedYet: true,
				},
				{
					Name:        "pkg6",
					FixState:    "Out of support scope",
					NotFixedYet: true,
				},
			},
		},
		{
			name: "cpe not match",
			args: args{
				ps: []gostmodels.RedhatPackageState{
					{
						FixState:    "New",
						PackageName: "pkg1",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
					{
						FixState:    "Under investigation",
						PackageName: "pkg2",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
				},
				installed: models.Packages{"pkg1": models.Package{}, "pkg2": models.Package{}},
				release:   "9.1",
			},
		},
		{
			name: "not in installed",
			args: args{
				ps: []gostmodels.RedhatPackageState{
					{
						FixState:    "Affected",
						PackageName: "pkg2",
						Cpe:         "cpe:/o:redhat:enterprise_linux:8",
					},
				},
				installed: models.Packages{"pkg": models.Package{Name: "pkg"}},
				release:   "8.1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (RedHat{}).mergePackageStates(models.VulnInfo{}, tt.args.ps, tt.args.installed, tt.args.release); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RedHat.mergePackageStates() = %v, want %v", got, tt.want)
			}
		})
	}
}
