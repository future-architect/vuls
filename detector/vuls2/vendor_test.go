package vuls2

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/constant"
	"github.com/future-architect/vuls/models"
)

func Test_MacOSCPEs(t *testing.T) {
	type args struct {
		r *models.ScanResult
	}
	tests := []struct {
		name string
		args args
		want []CPE
	}{
		{
			name: "macOS with OS and Safari",
			args: args{r: &models.ScanResult{
				Family:  constant.MacOS,
				Release: "13.0",
				Packages: models.Packages{
					"Safari": {Name: "Safari", Version: "16.0", Repository: "com.apple.Safari"},
				},
			}},
			want: []CPE{
				{URI: "cpe:/o:apple:macos:13.0"},
				{URI: "cpe:/o:apple:mac_os:13.0"},
				{URI: "cpe:/a:apple:safari:16.0::~~~macos~~"},
				{URI: "cpe:/a:apple:safari:16.0::~~~mac_os~~"},
			},
		},
		{
			name: "package without version is skipped",
			args: args{r: &models.ScanResult{
				Family:  constant.MacOSX,
				Release: "10.15.7",
				Packages: models.Packages{
					"Safari": {Name: "Safari", Version: "", Repository: "com.apple.Safari"},
				},
			}},
			want: []CPE{
				{URI: "cpe:/o:apple:mac_os_x:10.15.7"},
			},
		},
		{
			name: "empty release without apps yields no CPEs",
			args: args{r: &models.ScanResult{Family: constant.MacOS, Release: ""}},
			want: nil,
		},
		{
			name: "empty release still detects applications",
			args: args{r: &models.ScanResult{
				Family:  constant.MacOS,
				Release: "",
				Packages: models.Packages{
					"Safari": {Name: "Safari", Version: "16.0", Repository: "com.apple.Safari"},
				},
			}},
			want: []CPE{
				{URI: "cpe:/a:apple:safari:16.0::~~~macos~~"},
				{URI: "cpe:/a:apple:safari:16.0::~~~mac_os~~"},
			},
		},
		{
			name: "non-macOS family yields no CPEs",
			args: args{r: &models.ScanResult{Family: constant.Ubuntu, Release: "22.04"}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MacOSCPEs(tt.args.r); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MacOSCPEs() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
