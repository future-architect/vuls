package gost

import (
	"reflect"
	"testing"
	"time"

	"github.com/future-architect/vuls/models"
	gostmodels "github.com/vulsio/gost/models"
)

func TestUbuntu_Supported(t *testing.T) {
	tests := []struct {
		name string
		args string
		want bool
	}{
		{
			name: "14.04 is supported",
			args: "1404",
			want: true,
		},
		{
			name: "16.04 is supported",
			args: "1604",
			want: true,
		},
		{
			name: "18.04 is supported",
			args: "1804",
			want: true,
		},
		{
			name: "20.04 is supported",
			args: "2004",
			want: true,
		},
		{
			name: "20.10 is supported",
			args: "2010",
			want: true,
		},
		{
			name: "21.04 is supported",
			args: "2104",
			want: true,
		},
		{
			name: "empty string is not supported yet",
			args: "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ubu := Ubuntu{}
			if got := ubu.supported(tt.args); got != tt.want {
				t.Errorf("Ubuntu.Supported() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUbuntuConvertToModel(t *testing.T) {
	tests := []struct {
		name     string
		input    gostmodels.UbuntuCVE
		expected models.CveContent
	}{
		{
			name: "gost Ubuntu.ConvertToModel",
			input: gostmodels.UbuntuCVE{
				Candidate:  "CVE-2021-3517",
				PublicDate: time.Date(2021, 5, 19, 14, 15, 0, 0, time.UTC),
				References: []gostmodels.UbuntuReference{
					{Reference: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3517"},
					{Reference: "https://gitlab.gnome.org/GNOME/libxml2/-/issues/235"},
					{Reference: "https://gitlab.gnome.org/GNOME/libxml2/-/commit/bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2"}},
				Description: "description.",
				Notes:       []gostmodels.UbuntuNote{},
				Bugs:        []gostmodels.UbuntuBug{{Bug: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=987738"}},
				Priority:    "medium",
				Patches: []gostmodels.UbuntuPatch{
					{PackageName: "libxml2", ReleasePatches: []gostmodels.UbuntuReleasePatch{
						{ReleaseName: "focal", Status: "needed", Note: ""},
					}},
				},
				Upstreams: []gostmodels.UbuntuUpstream{{
					PackageName: "libxml2", UpstreamLinks: []gostmodels.UbuntuUpstreamLink{
						{Link: "https://gitlab.gnome.org/GNOME/libxml2/-/commit/50f06b3efb638efb0abd95dc62dca05ae67882c2"},
					},
				}},
			},
			expected: models.CveContent{
				Type:          models.UbuntuAPI,
				CveID:         "CVE-2021-3517",
				Summary:       "description.",
				Cvss2Severity: "medium",
				Cvss3Severity: "medium",
				SourceLink:    "https://ubuntu.com/security/CVE-2021-3517",
				References: []models.Reference{
					{Source: "CVE", Link: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3517"},
					{Link: "https://gitlab.gnome.org/GNOME/libxml2/-/issues/235"},
					{Link: "https://gitlab.gnome.org/GNOME/libxml2/-/commit/bf22713507fe1fc3a2c4b525cf0a88c2dc87a3a2"},
					{Source: "Bug", Link: "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=987738"},
					{Source: "UPSTREAM", Link: "https://gitlab.gnome.org/GNOME/libxml2/-/commit/50f06b3efb638efb0abd95dc62dca05ae67882c2"}},
				Published: time.Date(2021, 5, 19, 14, 15, 0, 0, time.UTC),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Ubuntu{}).ConvertToModel(&tt.input); !reflect.DeepEqual(got, &tt.expected) {
				t.Errorf("Ubuntu.ConvertToModel() = %#v, want %#v", got, &tt.expected)
			}
		})
	}
}

func TestUbuntu_detect(t *testing.T) {
	type args struct {
		fixed   map[string]gostmodels.UbuntuCVE
		unfixed map[string]gostmodels.UbuntuCVE
		srcPkg  models.SrcPackage
	}
	tests := []struct {
		name    string
		args    args
		want    []cveContent
		wantErr bool
	}{
		{
			name: "fixed",
			args: args{
				fixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "released", Note: "0.0.0-0"}},
							},
						},
					},
					"CVE-0000-0001": {
						Candidate: "CVE-0000-0001",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "released", Note: "0.0.0-2"}},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{
					Name:        "pkg",
					Version:     "0.0.0-1",
					BinaryNames: []string{"pkg"},
				},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{
						Type:       models.UbuntuAPI,
						CveID:      "CVE-0000-0001",
						SourceLink: "https://ubuntu.com/security/CVE-0000-0001",
						References: []models.Reference{},
					},
					fixStatuses: models.PackageFixStatuses{
						{
							Name:    "pkg",
							FixedIn: "0.0.0-2",
						},
					},
				},
			},
		},
		{
			name: "unfixed",
			args: args{
				unfixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "needed"}},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{
					Name:        "pkg",
					Version:     "0.0.0-1",
					BinaryNames: []string{"pkg"},
				},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{
						Type:       models.UbuntuAPI,
						CveID:      "CVE-0000-0000",
						SourceLink: "https://ubuntu.com/security/CVE-0000-0000",
						References: []models.Reference{},
					},
					fixStatuses: models.PackageFixStatuses{
						{
							Name:        "pkg",
							FixState:    "open",
							NotFixedYet: true,
						},
					},
				},
			},
		},
		{
			name: "linux-signed",
			args: args{
				fixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "linux",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "released", Note: "0.0.0-0"}},
							},
						},
					},
					"CVE-0000-0001": {
						Candidate: "CVE-0000-0001",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "linux",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "released", Note: "0.0.0-2"}},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{
					Name:        "linux-signed",
					Version:     "0.0.0-1",
					BinaryNames: []string{"linux-image-generic", "linux-headers-generic"},
				},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{
						Type:       models.UbuntuAPI,
						CveID:      "CVE-0000-0001",
						SourceLink: "https://ubuntu.com/security/CVE-0000-0001",
						References: []models.Reference{},
					},
					fixStatuses: models.PackageFixStatuses{
						{
							Name:    "linux-image-generic",
							FixedIn: "0.0.0-2",
						},
						{
							Name:    "linux-headers-generic",
							FixedIn: "0.0.0-2",
						},
					},
				},
			},
		},
		{
			name: "linux-meta",
			args: args{
				fixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "linux",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "released", Note: "0.0.0-0"}},
							},
						},
					},
					"CVE-0000-0001": {
						Candidate: "CVE-0000-0001",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "linux",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "released", Note: "0.0.0-2"}},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{
					Name:        "linux-meta",
					Version:     "0.0.0.1",
					BinaryNames: []string{"linux-image-generic", "linux-headers-generic"},
				},
			},
			want: nil,
		},
		{
			name: "fixed and unfixed, installed < fixed",
			args: args{
				fixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "esm-apps/focal", Status: "released", Note: "0.0.0-1"}},
							},
						},
					},
				},
				unfixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "focal", Status: "needed"}},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{
					Name:        "pkg",
					Version:     "0.0.0-0",
					BinaryNames: []string{"pkg"},
				},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{
						Type:       models.UbuntuAPI,
						CveID:      "CVE-0000-0000",
						SourceLink: "https://ubuntu.com/security/CVE-0000-0000",
						References: []models.Reference{},
					},
					fixStatuses: models.PackageFixStatuses{
						{
							Name:    "pkg",
							FixedIn: "0.0.0-1",
						},
					},
				},
			},
		},
		{
			name: "fixed and unfixed, installed > fixed",
			args: args{
				fixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "esm-apps/focal", Status: "released", Note: "0.0.0-1"}},
							},
						},
					},
				},
				unfixed: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "focal", Status: "needed"}},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{
					Name:        "pkg",
					Version:     "0.0.0-2",
					BinaryNames: []string{"pkg"},
				},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (Ubuntu{}).detect(tt.args.fixed, tt.args.unfixed, tt.args.srcPkg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Ubuntu.detect() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Ubuntu.detect() = %v, want %v", got, tt.want)
			}
		})
	}
}
