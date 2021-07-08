// +build !scanner

package oval

import (
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

func TestUpsert(t *testing.T) {
	var tests = []struct {
		res      ovalResult
		def      ovalmodels.Definition
		packName string
		fixStat  fixStat
		upsert   bool
		out      ovalResult
	}{
		//insert
		{
			res: ovalResult{},
			def: ovalmodels.Definition{
				DefinitionID: "1111",
			},
			packName: "pack1",
			fixStat: fixStat{
				notFixedYet: true,
				fixedIn:     "1.0.0",
			},
			upsert: false,
			out: ovalResult{
				[]defPacks{
					{
						def: ovalmodels.Definition{
							DefinitionID: "1111",
						},
						binpkgFixstat: map[string]fixStat{
							"pack1": {
								notFixedYet: true,
								fixedIn:     "1.0.0",
							},
						},
					},
				},
			},
		},
		//update
		{
			res: ovalResult{
				[]defPacks{
					{
						def: ovalmodels.Definition{
							DefinitionID: "1111",
						},
						binpkgFixstat: map[string]fixStat{
							"pack1": {
								notFixedYet: true,
								fixedIn:     "1.0.0",
							},
						},
					},
					{
						def: ovalmodels.Definition{
							DefinitionID: "2222",
						},
						binpkgFixstat: map[string]fixStat{
							"pack3": {
								notFixedYet: true,
								fixedIn:     "2.0.0",
							},
						},
					},
				},
			},
			def: ovalmodels.Definition{
				DefinitionID: "1111",
			},
			packName: "pack2",
			fixStat: fixStat{
				notFixedYet: false,
				fixedIn:     "3.0.0",
			},
			upsert: true,
			out: ovalResult{
				[]defPacks{
					{
						def: ovalmodels.Definition{
							DefinitionID: "1111",
						},
						binpkgFixstat: map[string]fixStat{
							"pack1": {
								notFixedYet: true,
								fixedIn:     "1.0.0",
							},
							"pack2": {
								notFixedYet: false,
								fixedIn:     "3.0.0",
							},
						},
					},
					{
						def: ovalmodels.Definition{
							DefinitionID: "2222",
						},
						binpkgFixstat: map[string]fixStat{
							"pack3": {
								notFixedYet: true,
								fixedIn:     "2.0.0",
							},
						},
					},
				},
			},
		},
	}
	for i, tt := range tests {
		upsert := tt.res.upsert(tt.def, tt.packName, tt.fixStat)
		if tt.upsert != upsert {
			t.Errorf("[%d]\nexpected: %t\n  actual: %t\n", i, tt.upsert, upsert)
		}
		if !reflect.DeepEqual(tt.out, tt.res) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, tt.res)
		}
	}
}

func TestDefpacksToPackStatuses(t *testing.T) {
	type in struct {
		dp    defPacks
		packs models.Packages
	}
	var tests = []struct {
		in  in
		out models.PackageFixStatuses
	}{
		// Ubuntu
		{
			in: in{
				dp: defPacks{
					def: ovalmodels.Definition{
						AffectedPacks: []ovalmodels.Package{
							{
								Name:        "a",
								NotFixedYet: true,
								Version:     "1.0.0",
							},
							{
								Name:        "b",
								NotFixedYet: false,
								Version:     "2.0.0",
							},
						},
					},
					binpkgFixstat: map[string]fixStat{
						"a": {
							notFixedYet: true,
							fixedIn:     "1.0.0",
							isSrcPack:   false,
						},
						"b": {
							notFixedYet: true,
							fixedIn:     "1.0.0",
							isSrcPack:   true,
							srcPackName: "lib-b",
						},
					},
				},
			},
			out: models.PackageFixStatuses{
				{
					Name:        "a",
					NotFixedYet: true,
					FixedIn:     "1.0.0",
				},
				{
					Name:        "b",
					NotFixedYet: true,
					FixedIn:     "1.0.0",
				},
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.dp.toPackStatuses()
		sort.Slice(actual, func(i, j int) bool {
			return actual[i].Name < actual[j].Name
		})
		if !reflect.DeepEqual(actual, tt.out) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}

func TestIsOvalDefAffected(t *testing.T) {
	type in struct {
		def    ovalmodels.Definition
		req    request
		family string
		kernel models.Kernel
		mods   []string
	}
	var tests = []struct {
		in          in
		affected    bool
		notFixedYet bool
		fixedIn     string
		wantErr     bool
	}{
		// 0. Ubuntu ovalpack.NotFixedYet == true
		{
			in: in{
				family: "ubuntu",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: true,
						},
						{
							Name:        "b",
							NotFixedYet: true,
							Version:     "1.0.0",
						},
					},
				},
				req: request{
					packName: "b",
				},
			},
			affected:    true,
			notFixedYet: true,
			fixedIn:     "1.0.0",
		},
		// 1. Ubuntu
		//   ovalpack.NotFixedYet == false
		//   req.isSrcPack == true
		//   Version comparison
		//     oval vs installed
		{
			in: in{
				family: "ubuntu",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "1.0.0-1",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      true,
					versionRelease: "1.0.0-0",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "1.0.0-1",
		},
		// 2. Ubuntu
		//   ovalpack.NotFixedYet == false
		//   Version comparison not hit
		//     oval vs installed
		{
			in: in{
				family: "ubuntu",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "1.0.0-1",
						},
					},
				},
				req: request{
					packName:       "b",
					versionRelease: "1.0.0-2",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 3. Ubuntu
		//   ovalpack.NotFixedYet == false
		//   req.isSrcPack == false
		//   Version comparison
		//     oval vs NewVersion
		//       oval.version > installed.newVersion
		{
			in: in{
				family: "ubuntu",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "1.0.0-3",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "1.0.0-0",
					newVersionRelease: "1.0.0-2",
				},
			},
			affected:    true,
			fixedIn:     "1.0.0-3",
			notFixedYet: false,
		},
		// 4. Ubuntu
		//   ovalpack.NotFixedYet == false
		//   req.isSrcPack == false
		//   Version comparison
		//     oval vs NewVersion
		//       oval.version < installed.newVersion
		{
			in: in{
				family: "ubuntu",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "1.0.0-2",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "1.0.0-0",
					newVersionRelease: "1.0.0-3",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "1.0.0-2",
		},
		// 5 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6_7.7",
					newVersionRelease: "",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 6 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6_7.6",
					newVersionRelease: "0:1.2.3-45.el6_7.7",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 7 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 8 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.9",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 9 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6_7.6",
					newVersionRelease: "0:1.2.3-45.el6_7.7",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 10 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6_7.6",
					newVersionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 11 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{Name: "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6_7.6",
					newVersionRelease: "0:1.2.3-45.el6_7.9",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 12 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 13 RedHat
		{
			in: in{
				family: "redhat",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 14 CentOS
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.centos.7",
					newVersionRelease: "",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 15
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.centos.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 16
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.centos.9",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 17
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.centos.6",
					newVersionRelease: "0:1.2.3-45.el6.centos.7",
				},
			},
			affected:    true,
			notFixedYet: true,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 18
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.centos.6",
					newVersionRelease: "0:1.2.3-45.el6.centos.8",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 19
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.centos.6",
					newVersionRelease: "0:1.2.3-45.el6.centos.9",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		// 20
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 21
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// 22
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.sl6.7",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.sl6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.sl6.9",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.sl6.6",
					newVersionRelease: "0:1.2.3-45.sl6.7",
				},
			},
			affected:    true,
			notFixedYet: true,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.sl6.6",
					newVersionRelease: "0:1.2.3-45.sl6.8",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.sl6.6",
					newVersionRelease: "0:1.2.3-45.sl6.9",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "centos",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// For kernel related packages, ignore OVAL with different major versions
		{
			in: in{
				family: constant.CentOS,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "kernel",
							Version:     "4.1.0",
							NotFixedYet: false,
						},
					},
				},
				req: request{
					packName:          "kernel",
					versionRelease:    "3.0.0",
					newVersionRelease: "3.2.0",
				},
				kernel: models.Kernel{
					Release: "3.0.0",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: constant.CentOS,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "kernel",
							Version:     "3.1.0",
							NotFixedYet: false,
						},
					},
				},
				req: request{
					packName:          "kernel",
					versionRelease:    "3.0.0",
					newVersionRelease: "3.2.0",
				},
				kernel: models.Kernel{
					Release: "3.0.0",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "3.1.0",
		},
		// Rocky Linux
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.rocky.7",
					newVersionRelease: "",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.rocky.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.rocky.9",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.rocky.6",
					newVersionRelease: "0:1.2.3-45.el6.rocky.7",
				},
			},
			affected:    true,
			notFixedYet: true,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.rocky.6",
					newVersionRelease: "0:1.2.3-45.el6.rocky.8",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.el6.rocky.6",
					newVersionRelease: "0:1.2.3-45.el6.rocky.9",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.sl6.7",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.sl6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.sl6.9",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.sl6.6",
					newVersionRelease: "0:1.2.3-45.sl6.7",
				},
			},
			affected:    true,
			notFixedYet: true,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.sl6.6",
					newVersionRelease: "0:1.2.3-45.sl6.8",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "0:1.2.3-45.sl6.6",
					newVersionRelease: "0:1.2.3-45.sl6.9",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "0:1.2.3-45.el6_7.8",
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6_7.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: "rocky",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "a",
							NotFixedYet: false,
						},
						{
							Name:        "b",
							NotFixedYet: false,
							Version:     "0:1.2.3-45.el6.8",
						},
					},
				},
				req: request{
					packName:       "b",
					isSrcPack:      false,
					versionRelease: "0:1.2.3-45.el6_7.8",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// For kernel related packages, ignore OVAL with different major versions
		{
			in: in{
				family: constant.Rocky,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "kernel",
							Version:     "4.1.0",
							NotFixedYet: false,
						},
					},
				},
				req: request{
					packName:          "kernel",
					versionRelease:    "3.0.0",
					newVersionRelease: "3.2.0",
				},
				kernel: models.Kernel{
					Release: "3.0.0",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		{
			in: in{
				family: constant.Rocky,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:        "kernel",
							Version:     "3.1.0",
							NotFixedYet: false,
						},
					},
				},
				req: request{
					packName:          "kernel",
					versionRelease:    "3.0.0",
					newVersionRelease: "3.2.0",
				},
				kernel: models.Kernel{
					Release: "3.0.0",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "3.1.0",
		},
		// dnf module
		{
			in: in{
				family: constant.RedHat,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:            "nginx",
							Version:         "1.16.1-1.module+el8.3.0+8844+e5e7039f.1",
							NotFixedYet:     false,
							ModularityLabel: "nginx:1.16",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "1.16.0-1.module+el8.3.0+8844+e5e7039f.1",
				},
				mods: []string{
					"nginx:1.16",
				},
			},
			affected:    true,
			notFixedYet: false,
			fixedIn:     "1.16.1-1.module+el8.3.0+8844+e5e7039f.1",
		},
		// dnf module 2
		{
			in: in{
				family: constant.RedHat,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:            "nginx",
							Version:         "1.16.1-1.module+el8.3.0+8844+e5e7039f.1",
							NotFixedYet:     false,
							ModularityLabel: "nginx:1.16",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "1.16.2-1.module+el8.3.0+8844+e5e7039f.1",
				},
				mods: []string{
					"nginx:1.16",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// dnf module 3
		{
			in: in{
				family: constant.RedHat,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:            "nginx",
							Version:         "1.16.1-1.module+el8.3.0+8844+e5e7039f.1",
							NotFixedYet:     false,
							ModularityLabel: "nginx:1.16",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "1.16.0-1.module+el8.3.0+8844+e5e7039f.1",
				},
				mods: []string{
					"nginx:1.14",
				},
			},
			affected:    false,
			notFixedYet: false,
		},
		// .ksplice1.
		{
			in: in{
				family: constant.Oracle,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2:2.17-106.0.1.ksplice1.el7_2.4",
							Arch:    "x86_64",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2:2.17-107",
					arch:           "x86_64",
				},
			},
			affected: false,
		},
		// .ksplice1.
		{
			in: in{
				family: constant.Oracle,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2:2.17-106.0.1.ksplice1.el7_2.4",
							Arch:    "x86_64",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2:2.17-105.0.1.ksplice1.el7_2.4",
					arch:           "x86_64",
				},
			},
			affected: true,
			fixedIn:  "2:2.17-106.0.1.ksplice1.el7_2.4",
		},
		// same arch
		{
			in: in{
				family: constant.Oracle,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2.17-106.0.1",
							Arch:    "x86_64",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2.17-105.0.1",
					arch:           "x86_64",
				},
			},
			affected: true,
			fixedIn:  "2.17-106.0.1",
		},
		// different arch
		{
			in: in{
				family: constant.Oracle,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2.17-106.0.1",
							Arch:    "aarch64",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2.17-105.0.1",
					arch:           "x86_64",
				},
			},
			affected: false,
			fixedIn:  "",
		},
		// Arch for RHEL, CentOS is ""
		{
			in: in{
				family: constant.RedHat,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2.17-106.0.1",
							Arch:    "",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2.17-105.0.1",
					arch:           "x86_64",
				},
			},
			affected: true,
			fixedIn:  "2.17-106.0.1",
		},
		// arch is empty for Oracle, Amazon linux
		{
			in: in{
				family: constant.Oracle,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2.17-106.0.1",
							Arch:    "",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2.17-105.0.1",
					arch:           "x86_64",
				},
			},
			wantErr: false,
			fixedIn: "",
		},
		// arch is empty for Oracle, Amazon linux
		{
			in: in{
				family: constant.Amazon,
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "nginx",
							Version: "2.17-106.0.1",
							Arch:    "",
						},
					},
				},
				req: request{
					packName:       "nginx",
					versionRelease: "2.17-105.0.1",
					arch:           "x86_64",
				},
			},
			wantErr: false,
			fixedIn: "",
		},
	}

	for i, tt := range tests {
		affected, notFixedYet, fixedIn, err := isOvalDefAffected(tt.in.def, tt.in.req, tt.in.family, tt.in.kernel, tt.in.mods)
		if tt.wantErr != (err != nil) {
			t.Errorf("[%d] err\nexpected: %t\n  actual: %s\n", i, tt.wantErr, err)
		}
		if tt.affected != affected {
			t.Errorf("[%d] affected\nexpected: %v\n  actual: %v\n", i, tt.affected, affected)
		}
		if tt.notFixedYet != notFixedYet {
			t.Errorf("[%d] notfixedyet\nexpected: %v\n  actual: %v\n", i, tt.notFixedYet, notFixedYet)
		}
		if tt.fixedIn != fixedIn {
			t.Errorf("[%d] fixedIn\nexpected: %v\n  actual: %v\n", i, tt.fixedIn, fixedIn)
		}
	}
}

func Test_rhelDownStreamOSVersionToRHEL(t *testing.T) {
	type args struct {
		ver string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "remove centos.",
			args: args{
				ver: "grub2-tools-2.02-0.80.el7.centos.x86_64",
			},
			want: "grub2-tools-2.02-0.80.el7.x86_64",
		},
		{
			name: "remove rocky.",
			args: args{
				ver: "platform-python-3.6.8-37.el8.rocky.x86_64",
			},
			want: "platform-python-3.6.8-37.el8.x86_64",
		},
		{
			name: "noop",
			args: args{
				ver: "grub2-tools-2.02-0.80.el7.x86_64",
			},
			want: "grub2-tools-2.02-0.80.el7.x86_64",
		},
		{
			name: "remove minor",
			args: args{
				ver: "sudo-1.8.23-10.el7_9.1",
			},
			want: "sudo-1.8.23-10.el7.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rhelDownStreamOSVersionToRHEL(tt.args.ver); got != tt.want {
				t.Errorf("rhelDownStreamOSVersionToRHEL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_lessThan(t *testing.T) {
	type args struct {
		family        string
		newVer        string
		AffectedPacks ovalmodels.Package
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "newVer and ovalmodels.Package both have underscoreMinorversion.",
			args: args{
				family: "centos",
				newVer: "1.8.23-10.el7_9.1",
				AffectedPacks: ovalmodels.Package{
					Name:        "sudo",
					Version:     "1.8.23-10.el7_9.1",
					NotFixedYet: false,
				},
			},
			want: false,
		},
		{
			name: "only newVer has underscoreMinorversion.",
			args: args{
				family: "centos",
				newVer: "1.8.23-10.el7_9.1",
				AffectedPacks: ovalmodels.Package{
					Name:        "sudo",
					Version:     "1.8.23-10.el7.1",
					NotFixedYet: false,
				},
			},
			want: false,
		},
		{
			name: "only ovalmodels.Package has underscoreMinorversion.",
			args: args{
				family: "centos",
				newVer: "1.8.23-10.el7.1",
				AffectedPacks: ovalmodels.Package{
					Name:        "sudo",
					Version:     "1.8.23-10.el7_9.1",
					NotFixedYet: false,
				},
			},
			want: false,
		},
		{
			name: "neither newVer nor ovalmodels.Package have underscoreMinorversion.",
			args: args{
				family: "centos",
				newVer: "1.8.23-10.el7.1",
				AffectedPacks: ovalmodels.Package{
					Name:        "sudo",
					Version:     "1.8.23-10.el7.1",
					NotFixedYet: false,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := lessThan(tt.args.family, tt.args.newVer, tt.args.AffectedPacks)
			if got != tt.want {
				t.Errorf("lessThan() = %t, want %t", got, tt.want)
			}
		})
	}
}

func Test_ovalResult_Sort(t *testing.T) {
	type fields struct {
		entries []defPacks
	}
	tests := []struct {
		name   string
		fields fields
		want   fields
	}{
		{
			name: "already sorted",
			fields: fields{
				entries: []defPacks{
					{def: ovalmodels.Definition{DefinitionID: "0"}},
					{def: ovalmodels.Definition{DefinitionID: "1"}},
				},
			},
			want: fields{
				entries: []defPacks{
					{def: ovalmodels.Definition{DefinitionID: "0"}},
					{def: ovalmodels.Definition{DefinitionID: "1"}},
				},
			},
		},
		{
			name: "sort",
			fields: fields{
				entries: []defPacks{
					{def: ovalmodels.Definition{DefinitionID: "1"}},
					{def: ovalmodels.Definition{DefinitionID: "0"}},
				},
			},
			want: fields{
				entries: []defPacks{
					{def: ovalmodels.Definition{DefinitionID: "0"}},
					{def: ovalmodels.Definition{DefinitionID: "1"}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &ovalResult{
				entries: tt.fields.entries,
			}
			o.Sort()

			if !reflect.DeepEqual(o.entries, tt.want.entries) {
				t.Errorf("act %#v, want %#v", o.entries, tt.want.entries)
			}
		})
	}
}
