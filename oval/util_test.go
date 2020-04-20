package oval

import (
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

func TestUpsert(t *testing.T) {
	var tests = []struct {
		res      ovalResult
		def      ovalmodels.Definition
		packName string
		fixStat  fixStat
		upserted bool
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
			upserted: false,
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
			upserted: true,
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
		upserted := tt.res.upsert(tt.def, tt.packName, tt.fixStat)
		if tt.upserted != upserted {
			t.Errorf("[%d]\nexpected: %t\n  actual: %t\n", i, tt.upserted, upserted)
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
	}
	var tests = []struct {
		in          in
		affected    bool
		notFixedYet bool
		fixedIn     string
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
				family: config.CentOS,
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
				family: config.CentOS,
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
	}
	for i, tt := range tests {
		affected, notFixedYet, fixedIn := isOvalDefAffected(tt.in.def, tt.in.req, tt.in.family, tt.in.kernel)
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

func TestMajor(t *testing.T) {
	var tests = []struct {
		in       string
		expected string
	}{
		{
			in:       "4.1",
			expected: "4",
		},
		{
			in:       "0:4.1",
			expected: "4",
		},
	}
	for i, tt := range tests {
		a := major(tt.in)
		if tt.expected != a {
			t.Errorf("[%d]\nexpected: %s\n  actual: %s\n", i, tt.expected, a)
		}
	}
}
