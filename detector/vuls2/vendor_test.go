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

func Test_jvnReferenceTitle(t *testing.T) {
	const url = "https://www.jpcert.or.jp/at/2021/at210050.html"
	type args struct {
		optional map[string]any
		url      string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "nil optional",
			args: args{optional: nil, url: url},
			want: "",
		},
		{
			name: "no reference_titles key",
			args: args{optional: map[string]any{"other": "x"}, url: url},
			want: "",
		},
		{
			name: "reference_titles map[string]any (as JSON-decoded from DB)",
			args: args{optional: map[string]any{"reference_titles": map[string]any{url: "Alert title"}}, url: url},
			want: "Alert title",
		},
		{
			name: "url not present in map",
			args: args{optional: map[string]any{"reference_titles": map[string]any{url: "Alert title"}}, url: "https://example.com/other"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := jvnReferenceTitle(tt.args.optional, tt.args.url); got != tt.want {
				t.Errorf("jvnReferenceTitle() = %q, want %q", got, tt.want)
			}
		})
	}
}
