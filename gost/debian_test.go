//go:build !scanner
// +build !scanner

package gost

import (
	"reflect"
	"testing"

	"golang.org/x/exp/slices"

	"github.com/future-architect/vuls/models"
	gostmodels "github.com/vulsio/gost/models"
)

func TestDebian_Supported(t *testing.T) {
	tests := []struct {
		name string
		args string
		want bool
	}{
		{
			name: "7 is supported",
			args: "7",
			want: true,
		},
		{
			name: "8 is supported",
			args: "8",
			want: true,
		},
		{
			name: "9 is supported",
			args: "9",
			want: true,
		},
		{
			name: "10 is supported",
			args: "10",
			want: true,
		},
		{
			name: "11 is supported",
			args: "11",
			want: true,
		},
		{
			name: "12 is supported",
			args: "12",
			want: true,
		},
		{
			name: "13 is not supported yet",
			args: "13",
			want: false,
		},
		{
			name: "14 is not supported yet",
			args: "14",
			want: false,
		},
		{
			name: "empty string is not supported yet",
			args: "",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Debian{}).supported(tt.args); got != tt.want {
				t.Errorf("Debian.Supported() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDebian_ConvertToModel(t *testing.T) {
	tests := []struct {
		name string
		args gostmodels.DebianCVE
		want models.CveContent
	}{
		{
			name: "gost Debian.ConvertToModel",
			args: gostmodels.DebianCVE{
				CveID:       "CVE-2022-39260",
				Scope:       "local",
				Description: "Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments into an array improperly uses an `int` to represent the number of entries in the array, allowing a malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version. Disabling `git shell` access via remote logins is a viable short-term workaround.",
				Package: []gostmodels.DebianPackage{
					{
						PackageName: "git",
						Release: []gostmodels.DebianRelease{
							{
								ProductName:  "bookworm",
								Status:       "resolved",
								FixedVersion: "1:2.38.1-1",
								Urgency:      "not yet assigned",
								Version:      "1:2.39.2-1.1",
							},
							{
								ProductName:  "bullseye",
								Status:       "resolved",
								FixedVersion: "1:2.30.2-1+deb11u1",
								Urgency:      "not yet assigned",
								Version:      "1:2.30.2-1",
							},
							{
								ProductName:  "buster",
								Status:       "resolved",
								FixedVersion: "1:2.20.1-2+deb10u5",
								Urgency:      "not yet assigned",
								Version:      "1:2.20.1-2+deb10u3",
							},
							{
								ProductName:  "sid",
								Status:       "resolved",
								FixedVersion: "1:2.38.1-1",
								Urgency:      "not yet assigned",
								Version:      "1:2.40.0-1",
							},
						},
					},
				},
			},
			want: models.CveContent{
				Type:          models.DebianSecurityTracker,
				CveID:         "CVE-2022-39260",
				Summary:       "Git is an open source, scalable, distributed revision control system. `git shell` is a restricted login shell that can be used to implement Git's push/pull functionality via SSH. In versions prior to 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4, the function that splits the command arguments into an array improperly uses an `int` to represent the number of entries in the array, allowing a malicious actor to intentionally overflow the return value, leading to arbitrary heap writes. Because the resulting array is then passed to `execv()`, it is possible to leverage this attack to gain remote code execution on a victim machine. Note that a victim must first allow access to `git shell` as a login shell in order to be vulnerable to this attack. This problem is patched in versions 2.30.6, 2.31.5, 2.32.4, 2.33.5, 2.34.5, 2.35.5, 2.36.3, and 2.37.4 and users are advised to upgrade to the latest version. Disabling `git shell` access via remote logins is a viable short-term workaround.",
				Cvss2Severity: "not yet assigned",
				Cvss3Severity: "not yet assigned",
				SourceLink:    "https://security-tracker.debian.org/tracker/CVE-2022-39260",
				Optional:      map[string]string{"attack range": "local"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (Debian{}).ConvertToModel(&tt.args); !reflect.DeepEqual(got, &tt.want) {
				t.Errorf("Debian.ConvertToModel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDebian_detect(t *testing.T) {
	type args struct {
		cves          map[string]gostmodels.DebianCVE
		srcPkg        models.SrcPackage
		runningKernel models.Kernel
	}
	tests := []struct {
		name string
		args args
		want []cveContent
	}{
		{
			name: "fixed",
			args: args{
				cves: map[string]gostmodels.DebianCVE{
					"CVE-0000-0000": {
						CveID: "CVE-0000-0000",
						Package: []gostmodels.DebianPackage{
							{
								PackageName: "pkg",
								Release: []gostmodels.DebianRelease{
									{
										ProductName:  "bullseye",
										Status:       "resolved",
										FixedVersion: "0.0.0-0",
									},
								},
							},
						},
					},
					"CVE-0000-0001": {
						CveID: "CVE-0000-0001",
						Package: []gostmodels.DebianPackage{
							{
								PackageName: "pkg",
								Release: []gostmodels.DebianRelease{
									{
										ProductName:  "bullseye",
										Status:       "resolved",
										FixedVersion: "0.0.0-2",
									},
								},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{Name: "pkg", Version: "0.0.0-1", BinaryNames: []string{"pkg"}},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.DebianSecurityTracker, CveID: "CVE-0000-0001", SourceLink: "https://security-tracker.debian.org/tracker/CVE-0000-0001"},
					fixStatuses: models.PackageFixStatuses{{
						Name:    "pkg",
						FixedIn: "0.0.0-2",
					}},
				},
			},
		},
		{
			name: "unfixed",
			args: args{
				cves: map[string]gostmodels.DebianCVE{
					"CVE-0000-0000": {
						CveID: "CVE-0000-0000",
						Package: []gostmodels.DebianPackage{
							{
								PackageName: "pkg",
								Release: []gostmodels.DebianRelease{
									{
										ProductName: "bullseye",
										Status:      "open",
									},
								},
							},
						},
					},
					"CVE-0000-0001": {
						CveID: "CVE-0000-0001",
						Package: []gostmodels.DebianPackage{
							{
								PackageName: "pkg",
								Release: []gostmodels.DebianRelease{
									{
										ProductName: "bullseye",
										Status:      "undetermined",
									},
								},
							},
						},
					},
				},
				srcPkg: models.SrcPackage{Name: "pkg", Version: "0.0.0-1", BinaryNames: []string{"pkg"}},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.DebianSecurityTracker, CveID: "CVE-0000-0000", SourceLink: "https://security-tracker.debian.org/tracker/CVE-0000-0000"},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "open",
						NotFixedYet: true,
					}},
				},
				{
					cveContent: models.CveContent{Type: models.DebianSecurityTracker, CveID: "CVE-0000-0001", SourceLink: "https://security-tracker.debian.org/tracker/CVE-0000-0001"},
					fixStatuses: models.PackageFixStatuses{{
						Name:        "pkg",
						FixState:    "undetermined",
						NotFixedYet: true,
					}},
				},
			},
		},
		{
			name: "linux-signed-amd64",
			args: args{
				cves: map[string]gostmodels.DebianCVE{
					"CVE-0000-0000": {
						CveID: "CVE-0000-0000",
						Package: []gostmodels.DebianPackage{
							{
								PackageName: "linux",
								Release: []gostmodels.DebianRelease{
									{
										ProductName:  "bullseye",
										Status:       "resolved",
										FixedVersion: "0.0.0-0",
									},
								},
							},
						},
					},
					"CVE-0000-0001": {
						CveID: "CVE-0000-0001",
						Package: []gostmodels.DebianPackage{
							{
								PackageName: "linux",
								Release: []gostmodels.DebianRelease{
									{
										ProductName:  "bullseye",
										Status:       "resolved",
										FixedVersion: "0.0.0-2",
									},
								},
							},
						},
					},
				},
				srcPkg:        models.SrcPackage{Name: "linux-signed-amd64", Version: "0.0.0+1", BinaryNames: []string{"linux-image-5.10.0-20-amd64"}},
				runningKernel: models.Kernel{Release: "5.10.0-20-amd64", Version: "0.0.0-1"},
			},
			want: []cveContent{
				{
					cveContent: models.CveContent{Type: models.DebianSecurityTracker, CveID: "CVE-0000-0001", SourceLink: "https://security-tracker.debian.org/tracker/CVE-0000-0001"},
					fixStatuses: models.PackageFixStatuses{{
						Name:    "linux-image-5.10.0-20-amd64",
						FixedIn: "0.0.0-2",
					}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := (Debian{}).detect(tt.args.cves, tt.args.srcPkg, tt.args.runningKernel)
			slices.SortFunc(got, func(i, j cveContent) int {
				if i.cveContent.CveID < j.cveContent.CveID {
					return -1
				}
				if i.cveContent.CveID > j.cveContent.CveID {
					return +1
				}
				return 0
			})
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Debian.detect() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDebian_isKernelSourcePackage(t *testing.T) {
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
			pkgname: "linux-5.10",
			want:    true,
		},
		{
			pkgname: "linux-grsec",
			want:    true,
		},
		{
			pkgname: "linux-base",
			want:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.pkgname, func(t *testing.T) {
			if got := (Debian{}).isKernelSourcePackage(tt.pkgname); got != tt.want {
				t.Errorf("Debian.isKernelSourcePackage() = %v, want %v", got, tt.want)
			}
		})
	}
}
