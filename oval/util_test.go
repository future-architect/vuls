//go:build !scanner

package oval

import (
	"reflect"
	"sort"
	"testing"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
	ovalmodels "github.com/vulsio/goval-dictionary/models"
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
		dp defPacks
	}
	var tests = []struct {
		in  in
		out models.PackageFixStatuses
	}{
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
		def     ovalmodels.Definition
		req     request
		family  string
		release string
	}
	var tests = []struct {
		in          in
		affected    bool
		notFixedYet bool
		fixState    string
		fixedIn     string
		wantErr     bool
	}{
		// arch is empty for Amazon linux
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
		// amazon linux 2 repository
		{
			in: in{
				family:  constant.Amazon,
				release: "2",
				def: ovalmodels.Definition{
					Advisory: ovalmodels.Advisory{
						AffectedRepository: "amzn2-core",
					},
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
					repository:     "amzn2-core",
				},
			},
			affected: true,
			fixedIn:  "2.17-106.0.1",
		},
		{
			in: in{
				family:  constant.Amazon,
				release: "2",
				def: ovalmodels.Definition{
					Advisory: ovalmodels.Advisory{
						AffectedRepository: "amzn2-core",
					},
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
					repository:     "amzn2extra-nginx",
				},
			},
			affected: false,
			fixedIn:  "",
		},
		{
			in: in{
				family:  constant.SUSEEnterpriseServer,
				release: "12.3",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "kernel-default",
							Version: "0:4.4.140-96.98",
						},
					},
				},
				req: request{
					packName:       "kernel-default",
					versionRelease: "0:4.4.140-96.97",
					arch:           "x86_64",
				},
			},
			affected: true,
			fixedIn:  "0:4.4.140-96.98",
		},
		{
			in: in{
				family:  constant.SUSEEnterpriseServer,
				release: "12.3",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "kernel-default",
							Version: "0:4.4.140-96.97.TDC.1",
						},
					},
				},
				req: request{
					packName:       "kernel-default",
					versionRelease: "0:4.4.140-96.97",
					arch:           "x86_64",
				},
			},
			affected: false,
		},
		{
			in: in{
				family:  constant.SUSEEnterpriseServer,
				release: "12.3",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "kernel-default",
							Version: "0:4.4.180-94.156.1",
						},
					},
				},
				req: request{
					packName:       "kernel-default",
					versionRelease: "0:4.4.140-96.126.TDC.1",
					arch:           "x86_64",
				},
			},
			affected: false,
		},
		{
			in: in{
				family:  constant.SUSEEnterpriseServer,
				release: "12.3",
				def: ovalmodels.Definition{
					AffectedPacks: []ovalmodels.Package{
						{
							Name:    "kernel-default",
							Version: "0:4.4.140-96.97.TDC.2",
						},
					},
				},
				req: request{
					packName:       "kernel-default",
					versionRelease: "0:4.4.140-96.97.TDC.1",
					arch:           "x86_64",
				},
			},
			affected: true,
			fixedIn:  "0:4.4.140-96.97.TDC.2",
		},
	}

	for i, tt := range tests {
		affected, notFixedYet, fixState, fixedIn, err := isOvalDefAffected(tt.in.def, tt.in.req, tt.in.family, tt.in.release)
		if tt.wantErr != (err != nil) {
			t.Errorf("[%d] err\nexpected: %t\n  actual: %s\n", i, tt.wantErr, err)
		}
		if tt.affected != affected {
			t.Errorf("[%d] affected\nexpected: %v\n  actual: %v\n", i, tt.affected, affected)
		}
		if tt.notFixedYet != notFixedYet {
			t.Errorf("[%d] notfixedyet\nexpected: %v\n  actual: %v\n", i, tt.notFixedYet, notFixedYet)
		}
		if tt.fixState != fixState {
			t.Errorf("[%d] fixedState\nexpected: %v\n  actual: %v\n", i, tt.fixState, fixState)
		}
		if tt.fixedIn != fixedIn {
			t.Errorf("[%d] fixedIn\nexpected: %v\n  actual: %v\n", i, tt.fixedIn, fixedIn)
		}
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
			name: "amazon curl: 7.61.1-12.amzn2.0.2 = 7.61.1-12.amzn2.0.2",
			args: args{
				family: "amazon",
				newVer: "7.61.1-12.amzn2.0.2",
				AffectedPacks: ovalmodels.Package{
					Name:        "curl",
					Version:     "7.61.1-12.amzn2.0.2",
					Arch:        "x86_64",
					NotFixedYet: false,
				},
			},
			want: false,
		},
		{
			name: "amazon curl: 7.61.1-12.amzn2.0.2 < 7.61.1-12.amzn2.1",
			args: args{
				family: "amazon",
				newVer: "7.61.1-12.amzn2.0.2",
				AffectedPacks: ovalmodels.Package{
					Name:        "curl",
					Version:     "7.61.1-12.amzn2.1",
					NotFixedYet: false,
				},
			},
			want: true,
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

func TestParseCvss2(t *testing.T) {
	type out struct {
		score  float64
		vector string
	}
	var tests = []struct {
		in  string
		out out
	}{
		{
			in: "5/AV:N/AC:L/Au:N/C:N/I:N/A:P",
			out: out{
				score:  5.0,
				vector: "AV:N/AC:L/Au:N/C:N/I:N/A:P",
			},
		},
		{
			in: "",
			out: out{
				score:  0,
				vector: "",
			},
		},
	}
	for _, tt := range tests {
		s, v := parseCvss2(tt.in)
		if s != tt.out.score || v != tt.out.vector {
			t.Errorf("\nexpected: %f, %s\n  actual: %f, %s",
				tt.out.score, tt.out.vector, s, v)
		}
	}
}

func TestParseCvss3(t *testing.T) {
	type out struct {
		score  float64
		vector string
	}
	var tests = []struct {
		in  string
		out out
	}{
		{
			in: "5.6/CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
			out: out{
				score:  5.6,
				vector: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
			},
		},
		{
			in: "6.1/CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
			out: out{
				score:  6.1,
				vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
			},
		},
		{
			in: "",
			out: out{
				score:  0,
				vector: "",
			},
		},
	}
	for _, tt := range tests {
		s, v := parseCvss3(tt.in)
		if s != tt.out.score || v != tt.out.vector {
			t.Errorf("\nexpected: %f, %s\n  actual: %f, %s",
				tt.out.score, tt.out.vector, s, v)
		}
	}
}
