package gost

import (
	"reflect"
	"testing"
	"time"

	"golang.org/x/exp/slices"

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

func Test_detect(t *testing.T) {
	type args struct {
		cves                       map[string]gostmodels.UbuntuCVE
		srcPkg                     models.SrcPackage
		runningKernelBinaryPkgName string
	}
	tests := []struct {
		name string
		args args
		want []cveContent
	}{
		{
			name: "fixed",
			args: args{
				cves: map[string]gostmodels.UbuntuCVE{
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
				srcPkg:                     models.SrcPackage{Name: "pkg", Version: "0.0.0-1", BinaryNames: []string{"pkg"}},
				runningKernelBinaryPkgName: "",
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0001", SourceLink: "https://ubuntu.com/security/CVE-0000-0001", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:     "pkg",
						FixState: "released",
						FixedIn:  "0.0.0-2",
					}},
				},
			},
		},
		{
			name: "unfixed",
			args: args{
				cves: map[string]gostmodels.UbuntuCVE{
					"CVE-0000-0000": {
						Candidate: "CVE-0000-0000",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "needed"}},
							},
						},
					},
					"CVE-0000-0001": {
						Candidate: "CVE-0000-0001",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "deferred"}},
							},
						},
					},
					"CVE-0000-0002": {
						Candidate: "CVE-0000-0002",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "pending"}},
							},
						},
					},
					"CVE-0000-0003": {
						Candidate: "CVE-0000-0003",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "active"}},
							},
						},
					},
					"CVE-0000-0004": {
						Candidate: "CVE-0000-0004",
						Patches: []gostmodels.UbuntuPatch{
							{
								PackageName:    "pkg",
								ReleasePatches: []gostmodels.UbuntuReleasePatch{{ReleaseName: "jammy", Status: "ignored"}},
							},
						},
					},
				},
				srcPkg:                     models.SrcPackage{Name: "pkg", Version: "0.0.0-1", BinaryNames: []string{"pkg"}},
				runningKernelBinaryPkgName: "",
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0000", SourceLink: "https://ubuntu.com/security/CVE-0000-0000", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "needed",
						NotFixedYet: true,
					}},
				},
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0001", SourceLink: "https://ubuntu.com/security/CVE-0000-0001", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "deferred",
						NotFixedYet: true,
					}},
				},
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0002", SourceLink: "https://ubuntu.com/security/CVE-0000-0002", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "pending",
						NotFixedYet: true,
					}},
				},
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0003", SourceLink: "https://ubuntu.com/security/CVE-0000-0003", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "active",
						NotFixedYet: true,
					}},
				},
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0004", SourceLink: "https://ubuntu.com/security/CVE-0000-0004", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "ignored",
						NotFixedYet: true,
					}},
				},
			},
		},
		{
			name: "linux-signed",
			args: args{
				cves: map[string]gostmodels.UbuntuCVE{
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
				srcPkg:                     models.SrcPackage{Name: "linux-signed", Version: "0.0.0-1", BinaryNames: []string{"linux-image-generic", "linux-headers-generic"}},
				runningKernelBinaryPkgName: "linux-image-generic",
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0001", SourceLink: "https://ubuntu.com/security/CVE-0000-0001", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:     "linux-image-generic",
						FixState: "released",
						FixedIn:  "0.0.0-2",
					}},
				},
			},
		},
		{
			name: "linux-meta",
			args: args{
				cves: map[string]gostmodels.UbuntuCVE{
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
				srcPkg:                     models.SrcPackage{Name: "linux-meta", Version: "0.0.0.1", BinaryNames: []string{"linux-image-generic", "linux-headers-generic"}},
				runningKernelBinaryPkgName: "linux-image-generic",
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.UbuntuAPI, CveID: "CVE-0000-0001", SourceLink: "https://ubuntu.com/security/CVE-0000-0001", References: []models.Reference{}},
					fixStatuses: models.PackageFixStatuses{{
						Name:     "linux-image-generic",
						FixState: "released",
						FixedIn:  "0.0.0.2",
					}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (Ubuntu{}).detect(tt.args.cves, tt.args.srcPkg, tt.args.runningKernelBinaryPkgName)
			slices.SortFunc(got, func(i, j cveContent) bool {
				return i.cveContent.CveID < j.cveContent.CveID
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("detect() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestUbuntu_isKernelSourcePackage(t *testing.T) {
	tests := []struct {
		pkgname string
		want    bool
	}{
		{
			pkgname: "linux",
			want:    true,
		},
		{
			pkgname: "apt",
			want:    false,
		},
		{
			pkgname: "linux-aws",
			want:    true,
		},
		{
			pkgname: "linux-5.9",
			want:    true,
		},
		{
			pkgname: "linux-base",
			want:    false,
		},
		{
			pkgname: "apt-utils",
			want:    false,
		},
		{
			pkgname: "linux-aws-edge",
			want:    true,
		},
		{
			pkgname: "linux-aws-5.15",
			want:    true,
		},
		{
			pkgname: "linux-lowlatency-hwe-5.15",
			want:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.pkgname, func(t *testing.T) {
			if got := (Ubuntu{}).isKernelSourcePackage(tt.pkgname); got != tt.want {
				t.Errorf("Ubuntu.isKernelSourcePackage() = %v, want %v", got, tt.want)
			}
		})
	}
}
