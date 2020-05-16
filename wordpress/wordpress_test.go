package wordpress

import (
	"github.com/k0kubun/pp"
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
)

func TestRemoveInactive(t *testing.T) {
	var tests = []struct {
		in       models.WordPressPackages
		expected models.WordPressPackages
	}{
		{
			in: models.WordPressPackages{
				{
					Name:    "akismet",
					Status:  "inactive",
					Update:  "",
					Version: "",
					Type:    "",
				},
			},
			expected: nil,
		},
		{
			in: models.WordPressPackages{
				{
					Name:    "akismet",
					Status:  "inactive",
					Update:  "",
					Version: "",
					Type:    "",
				},
				{
					Name:    "BackWPup",
					Status:  "inactive",
					Update:  "",
					Version: "",
					Type:    "",
				},
			},
			expected: nil,
		},
		{
			in: models.WordPressPackages{
				{
					Name:    "akismet",
					Status:  "active",
					Update:  "",
					Version: "",
					Type:    "",
				},
				{
					Name:    "BackWPup",
					Status:  "inactive",
					Update:  "",
					Version: "",
					Type:    "",
				},
			},
			expected: models.WordPressPackages{
				{
					Name:    "akismet",
					Status:  "active",
					Update:  "",
					Version: "",
					Type:    "",
				},
			},
		},
	}

	for i, tt := range tests {
		actual := removeInactives(tt.in)
		if !reflect.DeepEqual(actual, tt.expected) {
			pp.Print(tt.expected)
			pp.Print(actual)
			t.Errorf("[%d] WordPressPackages error ", i)
		}
	}
}
