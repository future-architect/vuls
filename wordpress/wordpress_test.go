package wordpress

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
)

func TestFillInactive(t *testing.T) {
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
			expected: models.WordPressPackages{},
		},
	}

	for i, tt := range tests {
		actual := fillInactives(tt.in)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("[%d] WordPressPackages error ", i)
		}
	}
}

func TestUnset(t *testing.T) {
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
			expected: models.WordPressPackages{},
		},
	}

	for i, tt := range tests {
		actual := unset(tt.in, 0)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("[%d] WordPressPackages error ", i)
		}
	}
}
