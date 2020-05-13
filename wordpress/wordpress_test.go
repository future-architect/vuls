package wordpress

import (
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
			expected: models.WordPressPackages{},
		},
	}

	for i, tt := range tests {
		actual := removeInactives(tt.in)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("[%d] WordPressPackages error ", i)
		}
	}
}

func TestRemoveAt(t *testing.T) {
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
		actual := removeAt(tt.in, 0)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("[%d] WordPressPackages error ", i)
		}
	}

	var boundrytests = []struct {
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
			expected: models.WordPressPackages{
				{
					Name:    "akismet",
					Status:  "inactive",
					Update:  "",
					Version: "",
					Type:    "",
				},
			},
		},
	}

	for i, tt := range boundrytests {
		actual := removeAt(tt.in, 1)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("[%d] boundrytests WordPressPackages error ", i)
		}
	}

	var emptytests = []struct {
		in       models.WordPressPackages
		expected models.WordPressPackages
	}{
		{
			in:       models.WordPressPackages{},
			expected: models.WordPressPackages{},
		},
	}

	for i, tt := range emptytests {
		actual := removeAt(tt.in, 1)
		if !reflect.DeepEqual(actual, tt.expected) {
			t.Errorf("[%d] emptytests WordPressPackages error ", i)
		}
	}
}
