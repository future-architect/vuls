package models

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/constant"
)

func TestIsDisplayUpdatableNum(t *testing.T) {
	var tests = []struct {
		mode     []byte
		family   string
		expected bool
	}{
		{
			mode:     []byte{config.Offline},
			expected: false,
		},
		{
			mode:     []byte{config.FastRoot},
			expected: true,
		},
		{
			mode:     []byte{config.Deep},
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.RedHat,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Oracle,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Debian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Ubuntu,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Raspbian,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.CentOS,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Amazon,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.FreeBSD,
			expected: false,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.OpenSUSE,
			expected: true,
		},
		{
			mode:     []byte{config.Fast},
			family:   constant.Alpine,
			expected: true,
		},
	}

	for i, tt := range tests {
		mode := config.ScanMode{}
		for _, m := range tt.mode {
			mode.Set(m)
		}
		r := ScanResult{
			ServerName: "name",
			Family:     tt.family,
		}
		act := r.isDisplayUpdatableNum(mode)
		if tt.expected != act {
			t.Errorf("[%d] expected %#v, actual %#v", i, tt.expected, act)
		}
	}
}

func TestRemoveRaspbianPackFromResult(t *testing.T) {
	var tests = []struct {
		in       ScanResult
		expected ScanResult
	}{
		{
			in: ScanResult{
				Family: constant.Raspbian,
				Packages: Packages{
					"apt":                Package{Name: "apt", Version: "1.8.2.1"},
					"libraspberrypi-dev": Package{Name: "libraspberrypi-dev", Version: "1.20200811-1"},
				},
				SrcPackages: SrcPackages{},
			},
			expected: ScanResult{
				Family: constant.Raspbian,
				Packages: Packages{
					"apt": Package{Name: "apt", Version: "1.8.2.1"},
				},
				SrcPackages: SrcPackages{},
			},
		},
		{
			in: ScanResult{
				Family: constant.Debian,
				Packages: Packages{
					"apt": Package{Name: "apt", Version: "1.8.2.1"},
				},
				SrcPackages: SrcPackages{},
			},
			expected: ScanResult{
				Family: constant.Debian,
				Packages: Packages{
					"apt": Package{Name: "apt", Version: "1.8.2.1"},
				},
				SrcPackages: SrcPackages{},
			},
		},
	}

	for i, tt := range tests {
		r := tt.in
		r = *r.RemoveRaspbianPackFromResult()
		if !reflect.DeepEqual(r, tt.expected) {
			t.Errorf("[%d] expected %+v, actual %+v", i, tt.expected, r)
		}
	}
}
