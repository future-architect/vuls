package oval

import (
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/kotakanbe/goval-dictionary/models"
)

func TestUpsert(t *testing.T) {
	var tests = []struct {
		res         ovalResult
		def         ovalmodels.Definition
		packName    string
		notFixedYet bool
		upserted    bool
		out         ovalResult
	}{
		//insert
		{
			res: ovalResult{},
			def: ovalmodels.Definition{
				DefinitionID: "1111",
			},
			packName:    "pack1",
			notFixedYet: true,
			upserted:    false,
			out: ovalResult{
				[]defPacks{
					{
						def: ovalmodels.Definition{
							DefinitionID: "1111",
						},
						actuallyAffectedPackNames: map[string]bool{
							"pack1": true,
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
						actuallyAffectedPackNames: map[string]bool{
							"pack1": true,
						},
					},
					{
						def: ovalmodels.Definition{
							DefinitionID: "2222",
						},
						actuallyAffectedPackNames: map[string]bool{
							"pack3": true,
						},
					},
				},
			},
			def: ovalmodels.Definition{
				DefinitionID: "1111",
			},
			packName:    "pack2",
			notFixedYet: false,
			upserted:    true,
			out: ovalResult{
				[]defPacks{
					{
						def: ovalmodels.Definition{
							DefinitionID: "1111",
						},
						actuallyAffectedPackNames: map[string]bool{
							"pack1": true,
							"pack2": false,
						},
					},
					{
						def: ovalmodels.Definition{
							DefinitionID: "2222",
						},
						actuallyAffectedPackNames: map[string]bool{
							"pack3": true,
						},
					},
				},
			},
		},
	}
	for i, tt := range tests {
		upserted := tt.res.upsert(tt.def, tt.packName, tt.notFixedYet)
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
		dp     defPacks
		family string
		packs  models.Packages
	}
	var tests = []struct {
		in  in
		out models.PackageStatuses
	}{
		// Ubuntu
		{
			in: in{
				family: "ubuntu",
				packs:  models.Packages{},
				dp: defPacks{
					def: ovalmodels.Definition{
						AffectedPacks: []ovalmodels.Package{
							{
								Name:        "a",
								NotFixedYet: true,
							},
							{
								Name:        "b",
								NotFixedYet: false,
							},
						},
					},
					actuallyAffectedPackNames: map[string]bool{
						"a": true,
						"b": true,
						"c": true,
					},
				},
			},
			out: models.PackageStatuses{
				{
					Name:        "a",
					NotFixedYet: true,
				},
				{
					Name:        "b",
					NotFixedYet: true,
				},
				{
					Name:        "c",
					NotFixedYet: true,
				},
			},
		},
	}
	for i, tt := range tests {
		actual := tt.in.dp.toPackStatuses(tt.in.family, tt.in.packs)
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
		family string
		req    request
	}
	var tests = []struct {
		in          in
		affected    bool
		notFixedYet bool
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
						},
					},
				},
				req: request{
					packName: "b",
				},
			},
			affected:    true,
			notFixedYet: true,
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
							Version:     "1.0.0-3",
						},
					},
				},
				req: request{
					packName:          "b",
					isSrcPack:         false,
					versionRelease:    "1.0.0-0",
					NewVersionRelease: "1.0.0-2",
				},
			},
			affected:    true,
			notFixedYet: true,
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
					NewVersionRelease: "1.0.0-3",
				},
			},
			affected:    true,
			notFixedYet: false,
		},
	}
	for i, tt := range tests {
		affected, notFixedYet := isOvalDefAffected(tt.in.def, tt.in.family, tt.in.req)
		if tt.affected != affected {
			t.Errorf("[%d] affected\nexpected: %v\n  actual: %v\n", i, tt.affected, affected)
		}
		if tt.notFixedYet != notFixedYet {
			t.Errorf("[%d] notfixedyet\nexpected: %v\n  actual: %v\n", i, tt.notFixedYet, notFixedYet)
		}
	}
}
