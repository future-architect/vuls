package config

import (
	"testing"
)

func TestToCpeURI(t *testing.T) {
	var tests = []struct {
		in       string
		expected string
		err      bool
	}{
		{
			in:       "",
			expected: "",
			err:      true,
		},
		{
			in:       "cpe:/a:microsoft:internet_explorer:10",
			expected: "cpe:/a:microsoft:internet_explorer:10",
			err:      false,
		},
		{
			in:       "cpe:2.3:a:microsoft:internet_explorer:10:*:*:*:*:*:*:*",
			expected: "cpe:/a:microsoft:internet_explorer:10",
			err:      false,
		},
	}

	for i, tt := range tests {
		actual, err := toCpeURI(tt.in)
		if err != nil && !tt.err {
			t.Errorf("[%d] unexpected error occurred, in: %s act: %s, exp: %s",
				i, tt.in, actual, tt.expected)
		} else if err == nil && tt.err {
			t.Errorf("[%d] expected error is not occurred, in: %s act: %s, exp: %s",
				i, tt.in, actual, tt.expected)
		}
		if actual != tt.expected {
			t.Errorf("[%d] in: %s, actual: %s, expected: %s",
				i, tt.in, actual, tt.expected)
		}
	}
}

func TestIsValidImage(t *testing.T) {
	var tests = []struct {
		name     string
		img      Image
		errOccur bool
	}{
		{
			name: "ok with tag",
			img: Image{
				Name: "ok",
				Tag:  "ok",
			},
			errOccur: false,
		},
		{
			name: "ok with digest",
			img: Image{
				Name:   "ok",
				Digest: "ok",
			},
			errOccur: false,
		},

		{
			name: "no image name with tag",
			img: Image{
				Tag: "ok",
			},
			errOccur: true,
		},

		{
			name: "no image name with digest",
			img: Image{
				Digest: "ok",
			},
			errOccur: true,
		},

		{
			name: "no tag and digest",
			img: Image{
				Name: "ok",
			},
			errOccur: true,
		},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := IsValidImage(tt.img)
			actual := err != nil
			if actual != tt.errOccur {
				t.Errorf("[%d] act: %v, exp: %v",
					i, actual, tt.errOccur)
			}
		})
	}
}
