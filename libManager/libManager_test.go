package libManager

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
	godeptypes "github.com/knqyf263/go-dep-parser/pkg/types"
)

func TestScan(t *testing.T) {
	var tests = []struct {
		path   string
		pkgs   []godeptypes.Library
		expect []models.VulnInfo
	}{
		{
			path: "app/package-lock.json",
			pkgs: []godeptypes.Library{
				{
					Name:    "jquery",
					Version: "2.2.4",
				},
				{
					Name:    "@babel/traverse",
					Version: "7.4.4",
				},
			},
		},
	}
	for _, v := range tests {
		actual, err := scan(v.path, v.pkgs)
		if err != nil {
			t.Errorf("error occured")
		}
		if !reflect.DeepEqual(v.expect, actual) {
			t.Errorf("\nexpected: %v\n  actual: %v\n", v.expect, actual)
		}
	}
}
