// +build !scanner

package gost

import (
	"reflect"
	"sort"
	"testing"
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
