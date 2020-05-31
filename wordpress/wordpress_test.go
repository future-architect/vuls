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
			t.Errorf("[%d] WordPressPackages error ", i)
		}
	}
}

func TestSearchCache(t *testing.T) {

	var tests = []struct {
		name        string
		wpVulnCache map[string]string
		value       string
		ok          bool
	}{
		{
			name: "akismet",
			wpVulnCache: map[string]string{
				"akismet": "body",
			},
			value: "body",
			ok:    true,
		},
		{
			name: "akismet",
			wpVulnCache: map[string]string{
				"BackWPup": "body",
				"akismet":  "body",
			},
			value: "body",
			ok:    true,
		},
		{
			name: "akismet",
			wpVulnCache: map[string]string{
				"BackWPup": "body",
			},
			value: "",
			ok:    false,
		},
		{
			name:        "akismet",
			wpVulnCache: nil,
			value:       "",
			ok:          false,
		},
	}

	for i, tt := range tests {
		value, ok := searchCache(tt.name, &tt.wpVulnCache)
		if value != tt.value || ok != tt.ok {
			t.Errorf("[%d] searchCache error ", i)
		}
	}
}
