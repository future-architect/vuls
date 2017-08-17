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
		res      ovalResult
		def      ovalmodels.Definition
		packName string
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
			upserted: false,
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
			packName: "pack2",
			upserted: true,
			out: ovalResult{
				[]defPacks{
					{
						def: ovalmodels.Definition{
							DefinitionID: "1111",
						},
						actuallyAffectedPackNames: map[string]bool{
							"pack1": true,
							"pack2": true,
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
		upserted := tt.res.upsert(tt.def, tt.packName)
		if tt.upserted != upserted {
			t.Errorf("[%d]\nexpected: %t\n  actual: %t\n", i, tt.upserted, upserted)
		}
		if !reflect.DeepEqual(tt.out, tt.res) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, tt.res)
		}
	}
}

func TestDefpacksToPackStatuses(t *testing.T) {
	var tests = []struct {
		in  defPacks
		out models.PackageStatuses
	}{
		{
			in: defPacks{
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
					"b": false,
				},
			},
			out: models.PackageStatuses{
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
	}
	for i, tt := range tests {
		actual := tt.in.toPackStatuses()
		sort.Slice(actual, func(i, j int) bool {
			return actual[i].Name < actual[j].Name
		})
		if !reflect.DeepEqual(actual, tt.out) {
			t.Errorf("[%d]\nexpected: %v\n  actual: %v\n", i, tt.out, actual)
		}
	}
}
