package vuls2_test

import (
	"cmp"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	kbcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	versioncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	exploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/exploit"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	remediationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/remediation"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	cvssV40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"

	"github.com/future-architect/vuls/detector/vuls2"
	testutil "github.com/future-architect/vuls/detector/vuls2/internal/test"
	"github.com/future-architect/vuls/models"
)

func Test_preConvertPkgs(t *testing.T) {
	type args struct {
		sr *models.ScanResult
	}
	tests := []struct {
		name string
		args args
		want scanTypes.ScanResult
	}{
		{
			name: "ubuntu 22.04, old scanner",
			args: args{
				sr: &models.ScanResult{
					ServerName: "jammy",
					Family:     "ubuntu",
					Release:    "22.04",
					RunningKernel: models.Kernel{
						Release:        "5.15.0-144-generic",
						Version:        "",
						RebootRequired: true,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name: "cron",
						},
					},
					SrcPackages: models.SrcPackages{
						"cron": models.SrcPackage{
							Name:        "cron",
							Version:     "3.0pl1-137ubuntu3",
							BinaryNames: []string{"cron"},
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "jammy",
				Family:      ecosystemTypes.Ecosystem("ubuntu"),
				Release:     "22.04",

				Kernel: scanTypes.Kernel{
					Release:        "5.15.0-144-generic",
					Version:        "",
					RebootRequired: true,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:       "cron",
						Version:    "0",
						SrcName:    "cron",
						SrcVersion: "3.0pl1-137ubuntu3",
					},
				},
			},
		},
		{
			name: "ubuntu 22.04",
			args: args{
				sr: &models.ScanResult{
					ServerName: "jammy",
					Family:     "ubuntu",
					Release:    "22.04",
					RunningKernel: models.Kernel{
						Release:        "5.15.0-144-generic",
						Version:        "",
						RebootRequired: true,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "cron",
							Version: "3.0pl1-137ubuntu3",
						},
					},
					SrcPackages: models.SrcPackages{
						"cron": models.SrcPackage{
							Name:        "cron",
							Version:     "3.0pl1-137ubuntu3",
							BinaryNames: []string{"cron"},
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "jammy",
				Family:      ecosystemTypes.Ecosystem("ubuntu"),
				Release:     "22.04",

				Kernel: scanTypes.Kernel{
					Release:        "5.15.0-144-generic",
					Version:        "",
					RebootRequired: true,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:       "cron",
						Version:    "3.0pl1-137ubuntu3",
						SrcName:    "cron",
						SrcVersion: "3.0pl1-137ubuntu3",
					},
				},
			},
		},
		{
			name: "suse.linux.enterprise.server -> suse.linux.enterprise",
			args: args{
				sr: &models.ScanResult{
					ServerName: "sles-15",
					Family:     "suse.linux.enterprise.server",
					Release:    "15.3",
					RunningKernel: models.Kernel{
						Release:        "5.3.18-59.37-default",
						Version:        "",
						RebootRequired: false,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "sles-release",
							Version: "15.3",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "sles-15",
				Family:      ecosystemTypes.Ecosystem("suse.linux.enterprise"),
				Release:     "15.3",

				Kernel: scanTypes.Kernel{
					Release:        "5.3.18-59.37-default",
					Version:        "",
					RebootRequired: false,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "sles-release",
						Version: "15.3",
					},
				},
			},
		},
		{
			name: "suse.linux.enterprise.desktop -> suse.linux.enterprise",
			args: args{
				sr: &models.ScanResult{
					ServerName: "sled-15",
					Family:     "suse.linux.enterprise.desktop",
					Release:    "15.3",
					RunningKernel: models.Kernel{
						Release:        "5.3.18-59.37-default",
						Version:        "",
						RebootRequired: false,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "sled-release",
							Version: "15.3",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "sled-15",
				Family:      ecosystemTypes.Ecosystem("suse.linux.enterprise"),
				Release:     "15.3",

				Kernel: scanTypes.Kernel{
					Release:        "5.3.18-59.37-default",
					Version:        "",
					RebootRequired: false,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "sled-release",
						Version: "15.3",
					},
				},
			},
		},
		{
			name: "opensuse:tumbleweed",
			args: args{
				sr: &models.ScanResult{
					ServerName: "tumbleweed",
					Family:     "opensuse",
					Release:    "tumbleweed",
					RunningKernel: models.Kernel{
						Release:        "5.3.18-59.37-default",
						Version:        "",
						RebootRequired: false,
					},
					Packages: models.Packages{
						"cron": models.Package{
							Name:    "openSUSE-release",
							Version: "20210101",
							Release: "0",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "tumbleweed",
				Family:      ecosystemTypes.EcosystemTypeOpenSUSETumbleweed,

				Kernel: scanTypes.Kernel{
					Release:        "5.3.18-59.37-default",
					Version:        "",
					RebootRequired: false,
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "openSUSE-release",
						Version: "20210101",
						Release: "0",
					},
				},
			},
		},
		{
			name: "amazon linux 2, old scanner with codename suffix",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2",
					Family:     "amazon",
					Release:    "2 (Karoo)",
					RunningKernel: models.Kernel{
						Release: "5.10.0-amzn2.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.7",
							Release: "19.amzn2.0.3",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2",

				Kernel: scanTypes.Kernel{
					Release: "5.10.0-amzn2.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.7",
						Release: "19.amzn2.0.3",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 2022, old scanner with codename suffix",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2022",
					Family:     "amazon",
					Release:    "2022 (Amazon Linux)",
					RunningKernel: models.Kernel{
						Release: "5.15.0-amzn2022.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.11",
							Release: "31.amzn2022.0.3",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2022",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2022",

				Kernel: scanTypes.Kernel{
					Release: "5.15.0-amzn2022.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.11",
						Release: "31.amzn2022.0.3",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 2023, new scanner",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2023",
					Family:     "amazon",
					Release:    "2023.3.20240312",
					RunningKernel: models.Kernel{
						Release: "6.1.0-amzn2023.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.13",
							Release: "1.amzn2023.0.1",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2023",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2023",

				Kernel: scanTypes.Kernel{
					Release: "6.1.0-amzn2023.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.13",
						Release: "1.amzn2023.0.1",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 1, old scanner with date-style release",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al1",
					Family:     "amazon",
					Release:    "2018.03",
					RunningKernel: models.Kernel{
						Release: "4.14.0-amzn1.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.8",
							Release: "10.32.amzn1",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al1",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "1",

				Kernel: scanTypes.Kernel{
					Release: "4.14.0-amzn1.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.8",
						Release: "10.32.amzn1",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "amazon linux 2, new scanner",
			args: args{
				sr: &models.ScanResult{
					ServerName: "al2",
					Family:     "amazon",
					Release:    "2",
					RunningKernel: models.Kernel{
						Release: "5.10.0-amzn2.x86_64",
					},
					Packages: models.Packages{
						"zlib": models.Package{
							Name:    "zlib",
							Version: "1.2.7",
							Release: "19.amzn2.0.3",
							Arch:    "x86_64",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "al2",
				Family:      ecosystemTypes.Ecosystem("amazon"),
				Release:     "2",

				Kernel: scanTypes.Kernel{
					Release: "5.10.0-amzn2.x86_64",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "zlib",
						Version: "1.2.7",
						Release: "19.amzn2.0.3",
						Arch:    "x86_64",
					},
				},
			},
		},
		{
			name: "windows -> microsoft with WindowsKB",
			args: args{
				sr: &models.ScanResult{
					ServerName: "win-server",
					Family:     "windows",
					Release:    "Windows 10 Version 21H2 for x64-based Systems",
					RunningKernel: models.Kernel{
						Version: "10.0.19044.1234",
					},
					WindowsKB: &models.WindowsKB{
						Applied:   []string{"5025288"},
						Unapplied: []string{"5025221"},
					},
					Packages: models.Packages{
						"Microsoft Edge": models.Package{
							Name:    "Microsoft Edge",
							Version: "128.0.2739.79",
						},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "win-server",
				Family:      ecosystemTypes.EcosystemTypeMicrosoft,
				Release:     "Windows 10 Version 21H2 for x64-based Systems",

				Kernel: scanTypes.Kernel{
					Version: "10.0.19044.1234",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "Microsoft Edge",
						Version: "128.0.2739.79",
					},
					{
						Name:    "Windows 10 Version 21H2 for x64-based Systems",
						Version: "10.0.19044.1234",
					},
				},
				MicrosoftKB: scanTypes.MicrosoftKB{
					Applied:   []string{"5025288"},
					Unapplied: []string{"5025221"},
				},
			},
		},
		{
			name: "windows without WindowsKB (nil)",
			args: args{
				sr: &models.ScanResult{
					ServerName: "win-server-no-kb",
					Family:     "windows",
					Release:    "Windows Server 2019",
					RunningKernel: models.Kernel{
						Version: "10.0.17763.1234",
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "win-server-no-kb",
				Family:      ecosystemTypes.EcosystemTypeMicrosoft,
				Release:     "Windows Server 2019",

				Kernel: scanTypes.Kernel{
					Version: "10.0.17763.1234",
				},
				OSPackages: []scanTypes.OSPackage{
					{
						Name:    "Windows Server 2019",
						Version: "10.0.17763.1234",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vuls2.PreConvertPkgs(tt.args.sr)
			if diff := gocmp.Diff(got, tt.want, gocmpopts.IgnoreFields(scanTypes.ScanResult{}, "ScannedAt", "ScannedBy")); diff != "" {
				t.Errorf("preConvertPkgs() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_preConvertCPEs(t *testing.T) {
	type args struct {
		sr   *models.ScanResult
		cpes []vuls2.CPE
	}
	tests := []struct {
		name      string
		args      args
		want      scanTypes.ScanResult
		wantMap   map[string][]string
		wantNoJVN map[string]struct{}
		wantErr   bool
	}{
		{
			// The OS-package / Microsoft-KB inputs stay empty even when the
			// scan result carries them — the CPE pass runs after
			// DetectPkgs already handled packages.
			name: "suppresses packages and KB",
			args: args{
				sr: &models.ScanResult{
					ServerName: "win-server",
					Family:     "windows",
					Release:    "Windows Server 2019",
					RunningKernel: models.Kernel{
						Version: "10.0.17763.1234",
					},
					Packages: models.Packages{
						"package1": {Name: "package1", Version: "0.0.1"},
					},
					WindowsKB: &models.WindowsKB{
						Applied:   []string{"0000001"},
						Unapplied: []string{"0000002"},
					},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "win-server",
				Family:      ecosystemTypes.EcosystemTypeMicrosoft,
				Release:     "Windows Server 2019",

				Kernel: scanTypes.Kernel{
					Version: "10.0.17763.1234",
				},
			},
		},
		{
			// URI inputs convert to the CPE 2.3 FS form vuls2 requires, FS
			// inputs pass through, and inputs normalising to the same FS
			// dedup in the detection list while the reverse map keeps every
			// user-supplied form for CpeURIs restoration.
			name: "converts URIs to FS and keeps every user form in the reverse map",
			args: args{
				sr: &models.ScanResult{
					ServerName: "cpe-server",
					Family:     "pseudo",
				},
				cpes: []vuls2.CPE{
					{URI: "cpe:/a:vendor:product:1.0", UseJVN: true},
					{URI: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", UseJVN: true},
					{URI: "cpe:/a:vendor:other:2.0", UseJVN: true},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "cpe-server",
				Family:      ecosystemTypes.Ecosystem("pseudo"),
				CPE: []string{
					"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*",
				},
			},
			wantMap: map[string][]string{
				"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:1.0", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
				"cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*":   {"cpe:/a:vendor:other:2.0"},
			},
		},
		{
			// UseJVN:false CPEs land in the no-JVN set (keyed by FS form); a CPE
			// with a UseJVN:true occurrence anywhere keeps JVN (true wins).
			name: "UseJVN:false populates the no-JVN set, true wins on conflict",
			args: args{
				sr: &models.ScanResult{
					ServerName: "cpe-server",
					Family:     "pseudo",
				},
				cpes: []vuls2.CPE{
					{URI: "cpe:/a:vendor:nojvn:1.0", UseJVN: false},
					{URI: "cpe:/a:vendor:withjvn:2.0", UseJVN: true},
					{URI: "cpe:/a:vendor:mixed:3.0", UseJVN: false},
					{URI: "cpe:/a:vendor:mixed:3.0", UseJVN: true},
				},
			},
			want: scanTypes.ScanResult{
				JSONVersion: 0,
				ServerName:  "cpe-server",
				Family:      ecosystemTypes.Ecosystem("pseudo"),
				CPE: []string{
					"cpe:2.3:a:vendor:nojvn:1.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:withjvn:2.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:mixed:3.0:*:*:*:*:*:*:*",
				},
			},
			wantMap: map[string][]string{
				"cpe:2.3:a:vendor:nojvn:1.0:*:*:*:*:*:*:*":   {"cpe:/a:vendor:nojvn:1.0"},
				"cpe:2.3:a:vendor:withjvn:2.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:withjvn:2.0"},
				"cpe:2.3:a:vendor:mixed:3.0:*:*:*:*:*:*:*":   {"cpe:/a:vendor:mixed:3.0"},
			},
			wantNoJVN: map[string]struct{}{
				"cpe:2.3:a:vendor:nojvn:1.0:*:*:*:*:*:*:*": {},
			},
		},
		{
			// Config-sourced CPEs were validated at config-load time, so an
			// unparseable entry signals an unvalidated caller input and
			// fails the conversion instead of silently detecting nothing.
			name: "unparseable CPE returns an error",
			args: args{
				sr: &models.ScanResult{
					ServerName: "cpe-server",
					Family:     "pseudo",
				},
				cpes: []vuls2.CPE{{URI: "cpe:/o:cisco:ios:15.1(4)m3", UseJVN: true}},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotMap, gotNoJVN, err := vuls2.PreConvertCPEs(tt.args.sr, tt.args.cpes)
			if (err != nil) != tt.wantErr {
				t.Fatalf("preConvertCPEs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := gocmp.Diff(got, tt.want, gocmpopts.IgnoreFields(scanTypes.ScanResult{}, "ScannedAt", "ScannedBy")); diff != "" {
				t.Errorf("preConvertCPEs() mismatch (-got +want):\n%s", diff)
			}
			if diff := gocmp.Diff(gotMap, tt.wantMap); diff != "" {
				t.Errorf("preConvertCPEs() reverse map mismatch (-got +want):\n%s", diff)
			}
			if diff := gocmp.Diff(gotNoJVN, tt.wantNoJVN); diff != "" {
				t.Errorf("preConvertCPEs() no-JVN set mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_postConvert(t *testing.T) {
	type args struct {
		scanned         scanTypes.ScanResult
		detected        detectTypes.DetectResult
		fsToOriginalCPE map[string][]string
		noJVNCPEs       map[string]struct{}
	}
	tests := []struct {
		name    string
		args    args
		want    models.VulnInfos
		wantErr bool
	}{
		{
			name: "redhat oval",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package3",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0002",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0002"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0002",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv1: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0003"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv2,
																CVSSv2: new(cvssV2Types.CVSSv2{
																	Vector:                   "AV:L/AC:L/Au:N/C:C/I:N/A:C",
																	BaseScore:                6.6,
																	NVDBaseSeverity:          "MEDIUM",
																	TemporalScore:            6.6,
																	NVDTemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:       6.6,
																	NVDEnvironmentalSeverity: "MEDIUM",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv30,
																CVSSv30: new(cvssV30Types.CVSSv30{
																	Vector:                "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package3",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{2},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0003"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv2,
																CVSSv2: new(cvssV2Types.CVSSv2{
																	Vector:                   "AV:L/AC:L/Au:N/C:C/I:N/A:C",
																	BaseScore:                6.6,
																	NVDBaseSeverity:          "MEDIUM",
																	TemporalScore:            6.6,
																	NVDTemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:       6.6,
																	NVDEnvironmentalSeverity: "MEDIUM",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv30,
																CVSSv30: new(cvssV30Types.CVSSv30{
																	Vector:                "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
											dataTypes.RootID("RHSA-2025:0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Affected",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package3",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{2},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "CRITICAL",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID:       "CVE-2025-0002",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
						{
							Name:        "package3",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "CRITICAL",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
						{
							AdvisoryID:  "RHSA-2025:0002",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0002",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    7.1,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0002",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0002",
										Source: "REDHAT",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0002",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0002",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}},{\"root_id\":\"RHSA-2025:0002\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0003": {
					CveID:       "CVE-2025-0003",
					Confidences: models.Confidences{models.OvalMatch},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0002",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
						{
							Name:        "package3",
							NotFixedYet: true,
							FixState:    "Affected",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:           models.RedHat,
								CveID:          "CVE-2025-0003",
								Title:          "title",
								Summary:        "description",
								Cvss2Score:     6.6,
								Cvss2Vector:    "AV:L/AC:L/Au:N/C:C/I:N/A:C",
								Cvss2Severity:  "MEDIUM",
								Cvss3Score:     7.1,
								Cvss3Vector:    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity:  "HIGH",
								Cvss40Score:    7.1,
								Cvss40Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
								Cvss40Severity: "HIGH",
								SourceLink:     "https://access.redhat.com/security/cve/CVE-2025-0003",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0003",
										Source: "REDHAT",
										RefID:  "CVE-2025-0003",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0002",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0002",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0003\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}},{\"root_id\":\"RHSA-2025:0002\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat vex",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("MEDIUM"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("HIGH"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1234560-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:2345601-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1234560-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:2345601-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:1234560-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:2345601-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0002",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0002"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:6543210-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("HIGH"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("MEDIUM"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1065432-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "RHSA-2025:0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0002"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("HIGH"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0002"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:6543210-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:1065432-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv40,
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
																	Score:    7.1,
																	Severity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:6543210-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-2.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-2.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-2.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-2.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:1065432-e6c7-e2d7-e6da-c772de020fa7"),
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "MEDIUM",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID:       "CVE-2025-0002",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-2.el9",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "HIGH",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
						{
							AdvisoryID:  "RHSA-2025:0002",
							Severity:    "HIGH",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:           models.RedHat,
								CveID:          "CVE-2025-0002",
								Title:          "title",
								Summary:        "description",
								Cvss3Score:     5.5,
								Cvss3Vector:    "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity:  "MEDIUM",
								Cvss40Score:    7.1,
								Cvss40Vector:   "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:N/VC:H/VI:N/VA:H/SC:H/SI:N/SA:H",
								Cvss40Severity: "HIGH",
								SourceLink:     "https://access.redhat.com/security/cve/CVE-2025-0002",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0002",
										Source: "REDHAT",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0002",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0002",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0002\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0654321-e6c7-e2d7-e6da-c772de020fa7\"}},{\"root_id\":\"CVE-2025-0002\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:abcdefg-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat oval + redhat vex",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("CRITICAL"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.1-0.el9",
																			},
																		},
																		Fixed: []string{"0.0.1-0.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.1-0.el9",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID:       "CVE-2025-0002",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Severity:    "CRITICAL",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0002",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0002",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0002",
										Source: "REDHAT",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat vex + epel",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "package2",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://www.cve.org/CVERecord?id=CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Affected",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "package",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
						{
							ID: "FEDORA-EPEL-2025-0123456789",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FEDORA-EPEL-2025-0123456789",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "FEDORA-EPEL-2025-0123456789",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Vendor: new("MEDIUM"),
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://www.cve.org/CVERecord?id=CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.FedoraAPI: {
											dataTypes.RootID("FEDORA-EPEL-2025-0123456789"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
																	BaseScore:             7.1,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.1,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.1,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://www.cve.org/CVERecord?id=CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("epel:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.FedoraAPI: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package2",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID: "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch, models.Confidence{
						Score:           100,
						DetectionMethod: models.DetectionMethod("EPELMatch"),
						SortOrder:       1,
					}},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: true,
							FixState:    "Affected",
						},
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "FEDORA-EPEL-2025-0123456789",
							Severity:    "MEDIUM",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:          models.RedHat,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"redhat-vex\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched:0123456-e6c7-e2d7-e6da-c772de020fa7\"}}]",
								},
							},
						},
						"epel": []models.CveContent{
							{
								Type:          "epel",
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    7.1,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity: "HIGH",
								References: models.References{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0001",
										Source: "CVE",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://bodhi.fedoraproject.org/updates/FEDORA-EPEL-2025-0123456789",
										Source: "FEDORA",
										RefID:  "FEDORA-EPEL-2025-0123456789",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FEDORA-EPEL-2025-0123456789\",\"source_id\":\"fedora-api\",\"segment\":{\"ecosystem\":\"epel:9\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0002": {
					CveID: "CVE-2025-0002",
					Confidences: models.Confidences{models.Confidence{
						Score:           100,
						DetectionMethod: models.DetectionMethod("EPELMatch"),
						SortOrder:       1,
					}},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package2",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "FEDORA-EPEL-2025-0123456789",
							Severity:    "MEDIUM",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						"epel": []models.CveContent{
							{
								Type:          "epel",
								CveID:         "CVE-2025-0002",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    7.1,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H",
								Cvss3Severity: "HIGH",
								References: models.References{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0002",
										Source: "CVE",
										RefID:  "CVE-2025-0002",
									},
									{
										Link:   "https://bodhi.fedoraproject.org/updates/FEDORA-EPEL-2025-0123456789",
										Source: "FEDORA",
										RefID:  "FEDORA-EPEL-2025-0123456789",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FEDORA-EPEL-2025-0123456789\",\"source_id\":\"fedora-api\",\"segment\":{\"ecosystem\":\"epel:9\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "redhat ignore pattern",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
						{
							Name:    "kpatch-patch-1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeNoneExist,
																		NoneExist: new(noneexistcriterionTypes.Criterion{
																			Type: noneexistcriterionTypes.PackageTypeBinary,
																			Binary: &necBinaryPackageTypes.Package{
																				Name:          "kpatch-patch-2",
																				Architectures: []string{"aarch64", "x86_64"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		NoneExist: true,
																	},
																},
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeVersion,
																		Version: new(versioncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: new(vcFixStatusTypes.FixStatus{
																				Class: vcFixStatusTypes.ClassFixed,
																			}),
																			Package: vcPackageTypes.Package{
																				Type: vcPackageTypes.PackageTypeBinary,
																				Binary: &vcBinaryPackageTypes.Package{
																					Name:          "package1",
																					Architectures: []string{"aarch64", "x86_64"},
																				},
																			},
																			Affected: &vcAffectedTypes.Affected{
																				Type: vcAffectedRangeTypes.RangeTypeRPM,
																				Range: []vcAffectedRangeTypes.Range{
																					{
																						LessThan: "0.0.0-1.el9",
																					},
																				},
																				Fixed: []string{"0.0.0-1.el9"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		Version: []int{0},
																	},
																},
															},
														},
														{
															Operator: criteriaTypes.CriteriaOperatorTypeOR,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeVersion,
																		Version: new(versioncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: new(vcFixStatusTypes.FixStatus{
																				Class: vcFixStatusTypes.ClassFixed,
																			}),
																			Package: vcPackageTypes.Package{
																				Type: vcPackageTypes.PackageTypeBinary,
																				Binary: &vcBinaryPackageTypes.Package{
																					Name:          "kpatch-patch-1",
																					Architectures: []string{"aarch64", "x86_64"},
																				},
																			},
																			Affected: &vcAffectedTypes.Affected{
																				Type: vcAffectedRangeTypes.RangeTypeRPM,
																				Range: []vcAffectedRangeTypes.Range{
																					{
																						LessThan: "0.0.0-1.el9",
																					},
																				},
																				Fixed: []string{"0.0.0-1.el9"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		Version: []int{1},
																	},
																},
															},
														},
														{
															Operator: criteriaTypes.CriteriaOperatorTypeOR,
															Criterions: []criterionTypes.FilteredCriterion{
																{
																	Criterion: criterionTypes.Criterion{
																		Type: criterionTypes.CriterionTypeVersion,
																		Version: new(versioncriterionTypes.Criterion{
																			Vulnerable: true,
																			FixStatus: new(vcFixStatusTypes.FixStatus{
																				Class: vcFixStatusTypes.ClassFixed,
																			}),
																			Package: vcPackageTypes.Package{
																				Type: vcPackageTypes.PackageTypeBinary,
																				Binary: &vcBinaryPackageTypes.Package{
																					Name:          "package1",
																					Architectures: []string{"aarch64", "x86_64"},
																				},
																			},
																			Affected: &vcAffectedTypes.Affected{
																				Type: vcAffectedRangeTypes.RangeTypeRPM,
																				Range: []vcAffectedRangeTypes.Range{
																					{
																						LessThan: "0.0.0-0.el9_1",
																					},
																				},
																				Fixed: []string{"0.0.0-0.el9_1"},
																			},
																		}),
																	},
																	Accepts: criterionTypes.AcceptQueries{
																		Version: []int{0},
																	},
																},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0002",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0002"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0002",
														Title:       "title",
														Description: "** REJECT ** description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0002"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0003",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0003"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0003",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "** REJECT ** description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0004",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "RHSA-2025:0004",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0004"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0004",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0004",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0005",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0005",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0005"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0005",
														Title:       "title",
														Description: "** REJECT ** description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0005",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Affected",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0006",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0006",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("CVE-2025-0006"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0006",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0006",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "Will not fix",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0007",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0007",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatVEXv1: {
											dataTypes.RootID("CVE-2025-0007"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0007",
														Title:       "title",
														Description: "[REJECTED CVE] description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0007",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched:gfedcba-e6c7-e2d7-e6da-c772de020fa7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatVEXv1: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched:gfedcba-e6c7-e2d7-e6da-c772de020fa7"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-0.el9_1",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0001",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:       models.RedHat,
								CveID:      "CVE-2025-0001",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://access.redhat.com/security/cve/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0001",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0001\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0003": {
					CveID:       "CVE-2025-0003",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0003",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:       models.RedHat,
								CveID:      "CVE-2025-0003",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://access.redhat.com/security/cve/CVE-2025-0003",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0003",
										Source: "REDHAT",
										RefID:  "CVE-2025-0003",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0003",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0003",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0003\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0004": {
					CveID:       "CVE-2025-0004",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RHSA-2025:0004",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:       models.RedHat,
								CveID:      "CVE-2025-0004",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://access.redhat.com/security/cve/CVE-2025-0004",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0004",
										Source: "REDHAT",
										RefID:  "CVE-2025-0004",
									},
									{
										Link:   "https://access.redhat.com/errata/RHSA-2025:0004",
										Source: "REDHAT",
										RefID:  "RHSA-2025:0004",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RHSA-2025:0004\",\"source_id\":\"redhat-ovalv2\",\"segment\":{\"ecosystem\":\"redhat:9\",\"tag\":\"rhel-9-including-unpatched\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "alma",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "ALSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "ALSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.AlmaErrata: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "ALSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOVAL: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "ALSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOSV: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "ALSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.AlmaErrata: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOVAL: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
										sourceTypes.AlmaOSV: {
											dataTypes.RootID("ALSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("alma:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.AlmaErrata: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
										sourceTypes.AlmaOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
										sourceTypes.AlmaOSV: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "ALSA-2025:0001",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.Alma: []models.CveContent{
							{
								Type:    models.Alma,
								CveID:   "CVE-2025-0001",
								Title:   "title",
								Summary: "description",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://errata.almalinux.org/9/ALSA-2025-0001.html",
										Source: "ALMA",
										RefID:  "ALSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"ALSA-2025:0001\",\"source_id\":\"alma-errata\",\"segment\":{\"ecosystem\":\"alma:9\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "rocky",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RLSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RLSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RockyErrata: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RLSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
										sourceTypes.RockyOSV: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: advisoryContentTypes.Content{
														ID:          "RLSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RockyErrata: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
										sourceTypes.RockyOSV: {
											dataTypes.RootID("RLSA-2025:0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("rocky:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RockyErrata: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
										sourceTypes.RockyOSV: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "package1",
							NotFixedYet: false,
							FixedIn:     "0.0.0-1.el9",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "RLSA-2025:0001",
							Issued:      time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "description",
						},
					},
					CveContents: models.CveContents{
						models.Rocky: []models.CveContent{
							{
								Type:    models.Rocky,
								CveID:   "CVE-2025-0001",
								Title:   "title",
								Summary: "description",
								References: models.References{
									{
										Link:   "https://access.redhat.com/security/cve/CVE-2025-0001",
										Source: "REDHAT",
										RefID:  "CVE-2025-0001",
									},
									{
										Link:   "https://errata.build.resf.org/RLSA-2025:0001",
										Source: "ROCKY",
										RefID:  "RLSA-2025:0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"RLSA-2025:0001\",\"source_id\":\"rocky-errata\",\"segment\":{\"ecosystem\":\"rocky:9\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ubuntu",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.15.0-69-generic",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "linux-headers-5.15.0-69",
							Version:    "5.15.0-69.76",
							SrcName:    "linux",
							SrcVersion: "5.15.0-69.76",
						},
						{
							Name:       "linux-headers-5.15.0-69-generic",
							Version:    "5.15.0-69.76",
							SrcName:    "linux",
							SrcVersion: "5.15.0-69.76",
						},
						{
							Name:       "linux-headers-generic",
							Version:    "5.15.0.69.67",
							SrcName:    "linux-meta",
							SrcVersion: "5.15.0.69.67",
						},
						{
							Name:       "linux-image-5.15.0-69-generic",
							Version:    "5.15.0-69.76",
							SrcName:    "linux-signed",
							SrcVersion: "5.15.0-69.76",
						},
						{
							Name:       "linux-image-5.15.0-33-generic",
							Version:    "5.15.0-33.34",
							SrcName:    "linux-signed",
							SrcVersion: "5.15.0-33.34",
						},
						{
							Name:       "linux-image-virtual",
							Version:    "5.15.0.69.67",
							SrcName:    "linux-meta",
							SrcVersion: "5.15.0.69.67",
						},
						{
							Name:       "bash",
							Version:    "5.1-6ubuntu1",
							SrcName:    "bash",
							SrcVersion: "5.1-6ubuntu1",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0002",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0002"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0002",
														Title:       "title",
														Description: "** REJECT ** description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "Rejected reason: description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0004",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0004",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnfixed,
																		Vendor: "ignored: end of kernel support",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 2, 3, 4, 5},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0005",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0005",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0005"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0005",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0005",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "fips-updates/jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77+fips.1",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77+fips.1"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "fips-updates/jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0006",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0006",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0006"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0006",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0006",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "esm-apps/jammy_low",
														},
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "fips-updates/jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77+esm.1",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77+esm.1"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "esm-apps/jammy_low",
											},
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-70.77+fips.1",
																			},
																		},
																		Fixed: []string{"5.15.0-70.77+fips.1"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0, 1, 3, 4},
															},
														},
													},
												},
												Tag: "fips-updates/jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0007",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0007",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0007"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0007",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0007",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "linux",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.15.0-69.76",
																			},
																		},
																		Fixed: []string{"5.15.0-69.76"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{4},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							ID: "CVE-2025-0008",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0008",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-0008"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0008",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-0008",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.1-6ubuntu2",
																			},
																		},
																		Fixed: []string{"5.1-6ubuntu2"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{6},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "linux-headers-5.15.0-69",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-headers-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-image-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-0001",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0001",
										Source: "CVE",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0006": {
					CveID:       "CVE-2025-0006",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "linux-headers-5.15.0-69",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-headers-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
						{
							Name:        "linux-image-5.15.0-69-generic",
							NotFixedYet: false,
							FixedIn:     "5.15.0-70.77",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-0006",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-0006",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0006",
										Source: "CVE",
										RefID:  "CVE-2025-0006",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0006\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
				"CVE-2025-0008": {
					CveID:       "CVE-2025-0008",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "bash",
							NotFixedYet: false,
							FixedIn:     "5.1-6ubuntu2",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-0008",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-0008",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-0008",
										Source: "CVE",
										RefID:  "CVE-2025-0008",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0008\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ubuntu needs-triage and not-affected should be filtered by vulnerable:false",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "bash",
							Version:    "5.1-6ubuntu1",
							SrcName:    "bash",
							SrcVersion: "5.1-6ubuntu1",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-1001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-1001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-1001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-1001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("low"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-1001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_low",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "5.1-6ubuntu2",
																			},
																		},
																		Fixed: []string{"5.1-6ubuntu2"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: "jammy_low",
											},
										},
									},
								},
							},
						},
						{
							// needs-triage: vulnerable=false, should NOT be detected
							ID: "CVE-2025-1002",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-1002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-1002"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-1002",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("medium"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-1002",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_medium",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// needs-triage: Vulnerable=false, Affected=nil
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: false,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassUnknown,
																		Vendor: "needs-triage",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: "jammy_medium",
											},
										},
									},
								},
							},
						},
						{
							// not-affected: vulnerable=false, should NOT be detected
							ID: "CVE-2025-1003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-1003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.UbuntuCVETracker: {
											dataTypes.RootID("CVE-2025-1003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-1003",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "launchpad.net/ubuntu-cve-tracker",
																Vendor: new("medium"),
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "launchpad.net/ubuntu-cve-tracker",
																URL:    "https://www.cve.org/CVERecord?id=CVE-2025-1003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
															Tag:       "jammy_medium",
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("ubuntu:22.04"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.UbuntuCVETracker: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// not-affected: Vulnerable=false, Affected=nil
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: false,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class:  vcFixStatusTypes.ClassNotAffected,
																		Vendor: "not-affected: code not present",
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "bash",
																		},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: "jammy_medium",
											},
										},
									},
								},
							},
						},
					},
				},
			},
			// Only CVE-2025-1001 (vulnerable:true) should appear.
			// CVE-2025-1002 (needs-triage, vulnerable:false) and CVE-2025-1003 (not-affected, vulnerable:false) should be filtered out.
			want: models.VulnInfos{
				"CVE-2025-1001": {
					CveID:       "CVE-2025-1001",
					Confidences: models.Confidences{models.UbuntuAPIMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "bash",
							NotFixedYet: false,
							FixedIn:     "5.1-6ubuntu2",
						},
					},
					CveContents: models.CveContents{
						models.UbuntuAPI: []models.CveContent{
							{
								Type:          models.UbuntuAPI,
								CveID:         "CVE-2025-1001",
								Title:         "title",
								Summary:       "description",
								Cvss2Severity: "low",
								Cvss3Severity: "low",
								SourceLink:    "https://ubuntu.com/security/CVE-2025-1001",
								References: []models.Reference{
									{
										Link:   "https://www.cve.org/CVERecord?id=CVE-2025-1001",
										Source: "CVE",
										RefID:  "CVE-2025-1001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-1001\",\"source_id\":\"ubuntu-cve-tracker\",\"segment\":{\"ecosystem\":\"ubuntu:22.04\",\"tag\":\"jammy_low\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "oracle",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.4.17-2102.200.13.el7uek.x86_64",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-tools",
							Version: "3.10.0",
							Release: "1160.24.1.el7",
							Arch:    "x86_64",
						},
						{
							Name:    "kernel-uek",
							Version: "5.4.17",
							Release: "2102.200.13.el7uek",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "ELSA-2022-7337",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "ELSA-2022-7337",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2022-7337"): {
												{
													Content: advisoryContentTypes.Content{
														ID: "ELSA-2022-7337",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-29901",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2022-7337"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2022-29901",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv30,
																CVSSv30: new(cvssV30Types.CVSSv30{
																	Vector:                "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
																	BaseScore:             5.6,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.6,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.6,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.Oracle: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "kernel-tools",
																			Architectures: []string{"x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0:3.10.0-1160.80.1.0.1.el7",
																			},
																		},
																		Fixed: []string{"0:3.10.0-1160.80.1.0.1.el7"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							ID: "ELSA-2025-20019",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "ELSA-2025-20019",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2025-20019"): {
												{
													Content: advisoryContentTypes.Content{
														ID: "ELSA-2025-20019",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-29901",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.Oracle: {
											dataTypes.RootID("ELSA-2025-20019"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2022-29901",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
																	BaseScore:             5.6,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.6,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.6,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("oracle:7"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.Oracle: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "kernel-uek",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0:5.4.17-2136.339.5.el7uek",
																			},
																		},
																		Fixed: []string{"0:5.4.17-2136.339.5.el7uek"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{1},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-29901": {
					CveID:       "CVE-2022-29901",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-tools",
							NotFixedYet: false,
							FixedIn:     "0:3.10.0-1160.80.1.0.1.el7",
						},
						{
							Name:        "kernel-uek",
							NotFixedYet: false,
							FixedIn:     "0:5.4.17-2136.339.5.el7uek",
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "ELSA-2022-7337",
							Issued:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
						{
							AdvisoryID: "ELSA-2025-20019",
							Issued:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Oracle: []models.CveContent{
							{
								Type:          models.Oracle,
								CveID:         "CVE-2022-29901",
								Cvss3Score:    5.6,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://linux.oracle.com/cve/CVE-2022-29901.html",
								References: models.References{
									{
										Link:   "https://linux.oracle.com/errata/ELSA-2022-7337.html",
										Source: "ORACLE",
										RefID:  "ELSA-2022-7337",
									},
									{
										Link:   "https://linux.oracle.com/errata/ELSA-2025-20019.html",
										Source: "ORACLE",
										RefID:  "ELSA-2025-20019",
									},
								},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"ELSA-2022-7337\",\"source_id\":\"oracle\",\"segment\":{\"ecosystem\":\"oracle:7\"}},{\"root_id\":\"ELSA-2025-20019\",\"source_id\":\"oracle\",\"segment\":{\"ecosystem\":\"oracle:7\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: prefer unfixed to fixed",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.18-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "binutils",
							Version: "2.37",
							Release: "7.26.1",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2022-4285",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "SUSE-CU-2023:3179-1",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2022-4285"): {
												{
													Content: advisoryContentTypes.Content{
														ID: "SUSE-CU-2023:3179-1",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-4285",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2022-4285"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2022-4285",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "SUSE",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: true,
																					FixStatus: new(vcFixStatusTypes.FixStatus{
																						Class: vcFixStatusTypes.ClassFixed,
																					}),
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "binutils",
																							Architectures: []string{
																								"aarch64",
																								"ppc64le",
																								"s390x",
																								"x86_64",
																							},
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPM,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								LessThan: "0:2.41-150100.7.46.1",
																							},
																						},
																						Fixed: []string{"0:2.41-150100.7.46.1"},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{0},
																			},
																		},
																	},
																},
															},
														},
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: true,
																					FixStatus: new(vcFixStatusTypes.FixStatus{
																						Class: vcFixStatusTypes.ClassUnfixed,
																					}),
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "binutils",
																							Architectures: []string{
																								"aarch64",
																								"ppc64le",
																								"s390x",
																								"x86_64",
																							},
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPM,
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{0},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-4285": {
					CveID:       "CVE-2022-4285",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "binutils",
							NotFixedYet: true,
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "SUSE-CU-2023:3179-1",
							Issued:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:          models.SUSE,
								CveID:         "CVE-2022-4285",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://www.suse.com/security/cve/CVE-2022-4285.html",
								References: models.References{
									{
										Link:   "https://www.suse.com/security/cve/SUSE-CU-2023:3179-1.html",
										Source: "SUSE",
										RefID:  "SUSE-CU-2023:3179-1",
									},
								},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2022-4285\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 1, in less-than range",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.17",
							Release: "59.37.2",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{0},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-33655": {
					CveID:       "CVE-2021-33655",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-default",
							NotFixedYet: false,
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:         models.SUSE,
								CveID:        "CVE-2021-33655",
								SourceLink:   "https://www.suse.com/security/cve/CVE-2021-33655.html",
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2021-33655\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 2, hit equals",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.18",
							Release: "150300.59.43.1",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{1},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{0},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-33655": {
					CveID:       "CVE-2021-33655",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-default",
							NotFixedYet: false,
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:         models.SUSE,
								CveID:        "CVE-2021-33655",
								SourceLink:   "https://www.suse.com/security/cve/CVE-2021-33655.html",
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2021-33655\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 3, livepatch is vulnerable",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.18",
							Release: "150300.59.43.1",
							Arch:    "x86_64",
						},
						{
							Name:    "kernel-livepatch-5_3_18-150300_59_43-default",
							Version: "15",
							Release: "150300.2.2-0",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{2},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{1},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: false,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{0},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-33655": {
					CveID:       "CVE-2021-33655",
					Confidences: models.Confidences{models.OvalMatch},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "kernel-default",
							NotFixedYet: false,
						},
						{
							Name:        "kernel-livepatch-5_3_18-150300_59_43-default",
							NotFixedYet: false,
						},
					},
					CveContents: models.CveContents{
						models.SUSE: []models.CveContent{
							{
								Type:         models.SUSE,
								CveID:        "CVE-2021-33655",
								SourceLink:   "https://www.suse.com/security/cve/CVE-2021-33655.html",
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2021-33655\",\"source_id\":\"suse-oval\",\"segment\":{\"ecosystem\":\"suse.linux.enterprise:15\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "suse: kernel livepatch 4, not vulnerable by livepatch",
			args: args{
				scanned: scanTypes.ScanResult{
					Kernel: scanTypes.Kernel{
						Release: "5.3.17-59.37-default",
					},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "kernel-default",
							Version: "5.3.18",
							Release: "150300.59.43.1",
							Arch:    "x86_64",
						},
						{
							Name:    "kernel-livepatch-5_3_18-150300_59_43-default",
							Version: "16",
							Release: "150300.2.2-0",
							Arch:    "x86_64",
						},
						{
							Name:    "sles-release",
							Version: "15.3",
							Release: "55.4.1",
							Arch:    "x86_64",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2021-33655",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2021-33655",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.SUSEOVAL: {
											dataTypes.RootID("CVE-2021-33655"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2021-33655",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("suse.linux.enterprise:15"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.SUSEOVAL: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterias: []criteriaTypes.FilteredCriteria{
														{
															Operator: criteriaTypes.CriteriaOperatorTypeAND,
															Criterias: []criteriaTypes.FilteredCriteria{
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterions: []criterionTypes.FilteredCriterion{
																		{
																			Criterion: criterionTypes.Criterion{
																				Type: criterionTypes.CriterionTypeVersion,
																				Version: new(versioncriterionTypes.Criterion{
																					Vulnerable: false,
																					Package: vcPackageTypes.Package{
																						Type: vcPackageTypes.PackageTypeBinary,
																						Binary: &vcBinaryPackageTypes.Package{
																							Name: "sles-release",
																						},
																					},
																					Affected: &vcAffectedTypes.Affected{
																						Type: vcAffectedRangeTypes.RangeTypeRPMVersionOnly,
																						Range: []vcAffectedRangeTypes.Range{
																							{
																								Equal: "15.3",
																							},
																						},
																					},
																				}),
																			},
																			Accepts: criterionTypes.AcceptQueries{
																				Version: []int{2},
																			},
																		},
																	},
																},
																{
																	Operator: criteriaTypes.CriteriaOperatorTypeOR,
																	Criterias: []criteriaTypes.FilteredCriteria{
																		{
																			Operator: criteriaTypes.CriteriaOperatorTypeOR,
																			Criterias: []criteriaTypes.FilteredCriteria{
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_43-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: false,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.43.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{0},
																							},
																						},
																					},
																				},
																				{
																					Operator: criteriaTypes.CriteriaOperatorTypeAND,
																					Criterias: []criteriaTypes.FilteredCriteria{
																						{
																							Operator: criteriaTypes.CriteriaOperatorTypeOR,
																							Criterions: []criterionTypes.FilteredCriterion{
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeVersion,
																										Version: new(versioncriterionTypes.Criterion{
																											Vulnerable: true,
																											FixStatus: new(vcFixStatusTypes.FixStatus{
																												Class: vcFixStatusTypes.ClassFixed,
																											}),
																											Package: vcPackageTypes.Package{
																												Type: vcPackageTypes.PackageTypeBinary,
																												Binary: &vcBinaryPackageTypes.Package{
																													Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																												},
																											},
																											Affected: &vcAffectedTypes.Affected{
																												Type: vcAffectedRangeTypes.RangeTypeRPM,
																												Range: []vcAffectedRangeTypes.Range{
																													{
																														LessThan: "0:16-150300.2.2-0",
																													},
																												},
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										Version: []int{},
																									},
																								},
																								{
																									Criterion: criterionTypes.Criterion{
																										Type: criterionTypes.CriterionTypeNoneExist,
																										NoneExist: new(noneexistcriterionTypes.Criterion{
																											Binary: &necBinaryPackageTypes.Package{
																												Name: "kernel-livepatch-5_3_18-150300_59_46-default",
																											},
																										}),
																									},
																									Accepts: criterionTypes.AcceptQueries{
																										NoneExist: true,
																									},
																								},
																							},
																						},
																					},
																					Criterions: []criterionTypes.FilteredCriterion{
																						{
																							Criterion: criterionTypes.Criterion{
																								Type: criterionTypes.CriterionTypeVersion,
																								Version: new(versioncriterionTypes.Criterion{
																									Vulnerable: true,
																									FixStatus: new(vcFixStatusTypes.FixStatus{
																										Class: vcFixStatusTypes.ClassFixed,
																									}),
																									Package: vcPackageTypes.Package{
																										Type: vcPackageTypes.PackageTypeBinary,
																										Binary: &vcBinaryPackageTypes.Package{
																											Name: "kernel-default",
																										},
																									},
																									Affected: &vcAffectedTypes.Affected{
																										Type: vcAffectedRangeTypes.RangeTypeRPM,
																										Range: []vcAffectedRangeTypes.Range{
																											{
																												Equal: "0:5.3.18-150300.59.46.1",
																											},
																										},
																									},
																								}),
																							},
																							Accepts: criterionTypes.AcceptQueries{
																								Version: []int{},
																							},
																						},
																					},
																				},
																			},
																			Criterions: []criterionTypes.FilteredCriterion{
																				{
																					Criterion: criterionTypes.Criterion{
																						Type: criterionTypes.CriterionTypeVersion,
																						Version: new(versioncriterionTypes.Criterion{
																							Vulnerable: true,
																							FixStatus: new(vcFixStatusTypes.FixStatus{
																								Class: vcFixStatusTypes.ClassFixed,
																							}),
																							Package: vcPackageTypes.Package{
																								Type: vcPackageTypes.PackageTypeBinary,
																								Binary: &vcBinaryPackageTypes.Package{
																									Name: "kernel-default",
																								},
																							},
																							Affected: &vcAffectedTypes.Affected{
																								Type: vcAffectedRangeTypes.RangeTypeRPM,
																								Range: []vcAffectedRangeTypes.Range{
																									{
																										LessThan: "0:5.3.18-59.40.1",
																									},
																								},
																							},
																						}),
																					},
																					Accepts: criterionTypes.AcceptQueries{
																						Version: []int{},
																					},
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			name: "redhat: all vulnerabilities ignored should not fallback to advisory",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "package1",
							Epoch:   new(0),
							Version: "0.0.0",
							Release: "0.el9",
							Arch:    "x86_64",
							SrcName: "package",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "RHSA-2025:0001",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "RHSA-2025:0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "RHSA-2025:0001",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.RedHatOVALv2: {
											dataTypes.RootID("RHSA-2025:0001"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "** REJECT ** This CVE has been rejected.",
														References: []referenceTypes.Reference{
															{
																URL: "https://access.redhat.com/security/cve/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
															Tag:       segmentTypes.DetectionTag("rhel-9-including-unpatched"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.RedHatOVALv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeBinary,
																		Binary: &vcBinaryPackageTypes.Package{
																			Name:          "package1",
																			Architectures: []string{"aarch64", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "0.0.0-1.el9",
																			},
																		},
																		Fixed: []string{"0.0.0-1.el9"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
												Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			name: "debian: advisory without vulnerability",
			args: args{
				scanned: scanTypes.ScanResult{
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "libxml2",
							Version:    "2.9.14+dfsg-1.3~deb12u1",
							SrcName:    "libxml2",
							SrcVersion: "2.9.14+dfsg-1.3~deb12u1",
						},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "DSA-5990-1",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "DSA-5990-1",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.DebianSecurityTrackerSalsa: {
											dataTypes.RootID("DSA-5990-1"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "DSA-5990-1",
														Description: "libxml2 security update",
														Published:   new(time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.Ecosystem("debian:12"),
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.Ecosystem("debian:12"),
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.DebianSecurityTrackerSalsa: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeVersion,
																Version: new(versioncriterionTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassFixed,
																	}),
																	Package: vcPackageTypes.Package{
																		Type: vcPackageTypes.PackageTypeSource,
																		Source: &vcSourcePackageTypes.Package{
																			Name: "libxml2",
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type: vcAffectedRangeTypes.RangeTypeDPKG,
																		Range: []vcAffectedRangeTypes.Range{
																			{
																				LessThan: "2.9.14+dfsg-1.3~deb12u4",
																			},
																		},
																		Fixed: []string{"2.9.14+dfsg-1.3~deb12u4"},
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																Version: []int{0},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"DSA-5990-1": {
					CveID: "DSA-5990-1",
					Confidences: models.Confidences{
						{
							Score:           100,
							DetectionMethod: "DebianSecurityTrackerMatch",
						},
					},
					AffectedPackages: models.PackageFixStatuses{
						{
							Name:        "libxml2",
							FixedIn:     "2.9.14+dfsg-1.3~deb12u4",
							NotFixedYet: false,
						},
					},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "DSA-5990-1",
							Description: "libxml2 security update",
							Issued:      time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.DebianSecurityTracker: []models.CveContent{
							{
								Type:       models.DebianSecurityTracker,
								CveID:      "DSA-5990-1",
								Summary:    "libxml2 security update",
								SourceLink: "https://security-tracker.debian.org/tracker/DSA-5990-1",
								References: models.References{
									{
										Link:   "https://security-tracker.debian.org/tracker/DSA-5990-1",
										Source: "DEBIAN",
										RefID:  "DSA-5990-1",
									},
								},
								Published:    time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional:     map[string]string{"vuls2-sources": `[{"root_id":"DSA-5990-1","source_id":"debian-security-tracker-salsa","segment":{"ecosystem":"debian:12"}}]`},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft kb detection: unapplied",
			args: args{
				scanned: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied:   []string{"5025288"},
						Unapplied: []string{"5025221"},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-21234",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-21234",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.MicrosoftCVRF: {
											dataTypes.RootID("CVE-2025-21234"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-21234",
														Title:       "Windows Win32k Elevation of Privilege Vulnerability",
														Description: "A privilege escalation vulnerability.",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
																	BaseScore:    7.8,
																	BaseSeverity: "HIGH",
																}),
															},
														},
														Published: new(time.Date(2025, 5, 13, 0, 0, 0, 0, time.UTC)),
														Optional:  map[string]any{"exploitability": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.MicrosoftCVRF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeKB,
																KB: &kbcriterionTypes.Criterion{
																	Product: "Windows 10 Version 21H2 for x64-based Systems",
																	KBID:    "5025221",
																},
															},
															Accepts: criterionTypes.AcceptQueries{
																KB: criterionTypes.KB{Unapplied: true},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-21234": {
					CveID:       "CVE-2025-21234",
					Confidences: models.Confidences{models.WindowsUpdateSearch},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "KB5025221",
							Description: "Microsoft Knowledge Base",
						},
					},
					WindowsKBFixedIns: []string{"KB5025221"},
					CveContents: models.CveContents{
						models.Microsoft: []models.CveContent{
							{
								Type:          models.Microsoft,
								CveID:         "CVE-2025-21234",
								Title:         "Windows Win32k Elevation of Privilege Vulnerability",
								Summary:       "A privilege escalation vulnerability.",
								Cvss3Score:    7.8,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21234",
								Published:     time.Date(2025, 5, 13, 0, 0, 0, 0, time.UTC),
								LastModified:  time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"exploit":       "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely",
									"vuls2-sources": `[{"root_id":"CVE-2025-21234","source_id":"microsoft-cvrf","segment":{"ecosystem":"microsoft"}}]`,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "microsoft kb detection: covered",
			args: args{
				scanned: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied:   []string{"5025221"},
						Unapplied: []string{},
					},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-21235",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-21235",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.MicrosoftCVRF: {
											dataTypes.RootID("CVE-2025-21235"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-21235",
														Title:       "Windows Kernel Information Disclosure Vulnerability",
														Description: "An information disclosure vulnerability.",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:       "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
																	BaseScore:    5.5,
																	BaseSeverity: "MEDIUM",
																}),
															},
														},
														Published: new(time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC)),
														Optional:  map[string]any{"exploitability": "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely"},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.MicrosoftCVRF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeKB,
																KB: &kbcriterionTypes.Criterion{
																	Product: "Windows 10 Version 21H2 for x64-based Systems",
																	KBID:    "5025288",
																},
															},
															Accepts: criterionTypes.AcceptQueries{
																KB: criterionTypes.KB{Covered: true},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-21235": {
					CveID:       "CVE-2025-21235",
					Confidences: models.Confidences{models.WindowsUpdateSearch},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "KB5025288",
							Description: "Microsoft Knowledge Base",
						},
					},
					WindowsKBFixedIns: []string{"KB5025288"},
					CveContents: models.CveContents{
						models.Microsoft: []models.CveContent{
							{
								Type:          models.Microsoft,
								CveID:         "CVE-2025-21235",
								Title:         "Windows Kernel Information Disclosure Vulnerability",
								Summary:       "An information disclosure vulnerability.",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21235",
								Published:     time.Date(2025, 6, 10, 0, 0, 0, 0, time.UTC),
								LastModified:  time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"exploit":       "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely",
									"vuls2-sources": `[{"root_id":"CVE-2025-21235","source_id":"microsoft-cvrf","segment":{"ecosystem":"microsoft"}}]`,
								},
							},
						},
					},
				},
			},
		},
		{
			// A cpe-ecosystem-only result: a version-restricted criterion
			// accepts -> ExactVersionMatch, the NVD content-level Exploit /
			// Mitigations slots map to models.Exploit / models.Mitigation,
			// and CpeURIs restores every user-supplied form (here the same
			// CPE was configured in both URI and FS form).
			name: "cpe exact accept with exploit/mitigation lift",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:0.0.0", "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0001"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0001",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             5.5,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5.5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5.5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														// NVD extractors lift "Exploit" / "Mitigation"
														// reference tags into these content slots; the
														// detector maps them to models.Exploit /
														// models.Mitigation (NVD content only).
														Mitigations: []remediationTypes.Remediation{
															{
																Source:      "nvd.nist.gov",
																Description: "https://example.com/mitigation",
															},
														},
														Exploit: []exploitTypes.Exploit{
															{
																Source: "nvd.nist.gov",
																Link:   "https://example.com/exploit",
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0001": {
					CveID:       "CVE-2025-0001",
					Confidences: models.Confidences{models.NvdExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:0.0.0", "cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeNVD,
							URL:         "https://example.com/exploit",
						},
					},
					Mitigations: []models.Mitigation{
						{
							CveContentType: models.Nvd,
							URL:            "https://example.com/mitigation",
						},
					},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:          models.Nvd,
								CveID:         "CVE-2025-0001",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    5.5,
								Cvss3Vector:   "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
								References: models.References{
									{
										Link:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0001",
										Source: "NVD",
										RefID:  "CVE-2025-0001",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0001\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// Cisco is advisory-shaped (content in advisories[], M:N with CVEs,
			// the vulnerability entry a bare CVE-ID stub), so the detection path
			// emits a DistroAdvisory plus a sparse per-CVE CveContent whose source
			// link points at the advisory (no CVSS/title/summary in the stub).
			name: "cpe cisco detection emits DistroAdvisory and CveContent (source link to advisory)",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:cisco:firepower_threat_defense:7.4.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:cisco:firepower_threat_defense:7.4.0.0:*:*:*:*:*:*:*": {"cpe:/a:cisco:firepower_threat_defense:7.4.0.0", "cpe:2.3:a:cisco:firepower_threat_defense:7.4.0.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "cisco-sa-3100_4200_tlsdos-2yNSCd54",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "cisco-sa-3100_4200_tlsdos-2yNSCd54",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.CiscoJSON: {
											dataTypes.RootID("cisco-sa-3100_4200_tlsdos-2yNSCd54"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "cisco-sa-3100_4200_tlsdos-2yNSCd54",
														Title:       "Cisco Secure Firewall Adaptive Security Appliance and Secure Firewall Threat Defense Software for Firepower 3100 and 4200 Series TLS 1.3 Cipher Denial of Service Vulnerability",
														Description: "A vulnerability in the TLS 1.3 implementation for a specific cipher for Cisco Secure Firewall ASA and FTD Software for Firepower 3100 and 4200 Series devices could allow an authenticated, remote attacker to cause a denial of service (DoS) condition.",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "cisco.com",
																Vendor: new("High"),
															},
														},
														CWE: []cweTypes.CWE{
															{
																Source: "cisco.com",
																CWE:    []string{"CWE-404"},
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "cisco.com",
																URL:    "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm91176",
															},
															{
																Source: "cisco.com",
																URL:    "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-3100_4200_tlsdos-2yNSCd54",
															},
														},
														Published: new(time.Date(2025, 8, 14, 16, 0, 0, 0, time.UTC)),
														Modified:  new(time.Date(2025, 9, 3, 13, 37, 50, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-20127",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.CiscoJSON: {
											dataTypes.RootID("cisco-sa-3100_4200_tlsdos-2yNSCd54"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2025-20127",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.CiscoJSON: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:cisco:firepower_threat_defense:*:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-20127": {
					CveID:       "CVE-2025-20127",
					Confidences: models.Confidences{models.CiscoExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:cisco:firepower_threat_defense:7.4.0.0", "cpe:2.3:a:cisco:firepower_threat_defense:7.4.0.0:*:*:*:*:*:*:*"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "cisco-sa-3100_4200_tlsdos-2yNSCd54",
							Severity:    "High",
							Issued:      time.Date(2025, 8, 14, 16, 0, 0, 0, time.UTC),
							Updated:     time.Date(2025, 9, 3, 13, 37, 50, 0, time.UTC),
							Description: "A vulnerability in the TLS 1.3 implementation for a specific cipher for Cisco Secure Firewall ASA and FTD Software for Firepower 3100 and 4200 Series devices could allow an authenticated, remote attacker to cause a denial of service (DoS) condition.",
						},
					},
					// Cisco is advisory-shaped: the vulnerability stub carries
					// only the CVE-ID, so the CveContent is sparse (no CVSS,
					// title, or summary) and its source link points at the
					// advisory (the root ID).
					CveContents: models.CveContents{
						models.Cisco: []models.CveContent{
							{
								Type:       models.Cisco,
								CveID:      "CVE-2025-20127",
								SourceLink: "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-3100_4200_tlsdos-2yNSCd54",
								References: models.References{
									{
										Link:   "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-3100_4200_tlsdos-2yNSCd54",
										Source: "CISCO",
										RefID:  "cisco-sa-3100_4200_tlsdos-2yNSCd54",
									},
								},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"cisco-sa-3100_4200_tlsdos-2yNSCd54\",\"source_id\":\"cisco-json\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// Palo Alto CVE roots carry rich vulnerability content (CVSS, CWE,
			// references) directly in the vulnerability stub, so the detection
			// path builds a full CveContent like any other CPE source. Its
			// source link is the per-CVE Palo Alto advisory page (keyed by the
			// CVE ID). No DistroAdvisory here: this root has no advisories[].
			name: "cpe paloalto detection emits CveContent with paloalto source link",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*": {"cpe:/o:paloaltonetworks:pan-os:10.0.0", "cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2022-0778",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2022-0778",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.PaloAltoJSON: {
											dataTypes.RootID("CVE-2022-0778"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2022-0778",
														Title:       "Impact of the OpenSSL Infinite Loop Vulnerability CVE-2022-0778",
														Description: "The Palo Alto Networks Product Security Assurance team has evaluated the OpenSSL infinite loop vulnerability.",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "security.paloaltonetworks.com",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
																	BaseScore:             7.5,
																	BaseSeverity:          "HIGH",
																	TemporalScore:         7.5,
																	TemporalSeverity:      "HIGH",
																	EnvironmentalScore:    7.5,
																	EnvironmentalSeverity: "HIGH",
																}),
															},
														},
														CWE: []cweTypes.CWE{
															{
																Source: "security.paloaltonetworks.com",
																CWE:    []string{"CWE-834"},
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "security.paloaltonetworks.com",
																URL:    "https://security.paloaltonetworks.com/CVE-2022-0778",
															},
														},
														Published: new(time.Date(2022, 3, 31, 2, 30, 0, 0, time.UTC)),
														Modified:  new(time.Date(2022, 6, 24, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.PaloAltoJSON: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"),
																	// Palo Alto criteria carry a pan-os version range
																	// (real CVE-2022-0778 shape); the scanned 10.0.0
																	// falls in [10.0.0, 10.0.10) -> exact match.
																	Range: new(ccRangeTypes.Range{
																		Type:         ccRangeTypes.RangeTypePANOS,
																		GreaterEqual: "10.0.0",
																		LessThan:     "10.0.10",
																	}),
																	Fixed: []string{"10.0.10"},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-0778": {
					CveID:       "CVE-2022-0778",
					Confidences: models.Confidences{models.PaloaltoExactVersionMatch},
					CpeURIs:     []string{"cpe:/o:paloaltonetworks:pan-os:10.0.0", "cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*"},
					CveContents: models.CveContents{
						models.Paloalto: []models.CveContent{
							{
								Type:          models.Paloalto,
								CveID:         "CVE-2022-0778",
								Title:         "Impact of the OpenSSL Infinite Loop Vulnerability CVE-2022-0778",
								Summary:       "The Palo Alto Networks Product Security Assurance team has evaluated the OpenSSL infinite loop vulnerability.",
								Cvss3Score:    7.5,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://security.paloaltonetworks.com/CVE-2022-0778",
								References: models.References{
									{
										Link:   "https://security.paloaltonetworks.com/CVE-2022-0778",
										Source: "MISC",
									},
								},
								CweIDs:       []string{"CWE-834"},
								Published:    time.Date(2022, 3, 31, 2, 30, 0, 0, time.UTC),
								LastModified: time.Date(2022, 6, 24, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2022-0778\",\"source_id\":\"paloalto-json\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// An advisory-shaped Palo Alto root: a PAN-SA bulletin with
			// advisories[] + detections[] but NO vulnerabilities[]. With no CVE
			// stub to drive the vulnerability loop, the advisory fallback builds
			// the VulnInfo keyed by the advisory ID: a DistroAdvisory plus a
			// CveContent synthesised from the advisory (Summary/SourceLink/refs
			// from the advisory, no CVSS). The DistroAdvisory Severity is empty
			// because Palo Alto advisory severity is CVSS (cvss_v40 here), not a
			// vendor SIR, and only vendor severity feeds DistroAdvisory.Severity.
			name: "cpe paloalto PAN-SA advisory (no vulnerabilities) emits DistroAdvisory + advisory CveContent",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*": {"cpe:/o:paloaltonetworks:pan-os:10.0.0", "cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "PAN-SA-2025-0003",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "PAN-SA-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.PaloAltoJSON: {
											dataTypes.RootID("PAN-SA-2025-0003"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "PAN-SA-2025-0003",
														Title:       "Informational: PAN-OS BIOS and Bootloader Security Bulletin",
														Description: "Palo Alto Networks is aware of claims of multiple vulnerabilities in PA-Series firewall firmware and bootloaders.",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv40,
																Source: "security.paloaltonetworks.com",
																CVSSv40: new(cvssV40Types.CVSSv40{
																	Vector:   "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
																	Score:    0,
																	Severity: "NONE",
																}),
															},
														},
														Published: new(time.Date(2025, 1, 23, 23, 20, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.PaloAltoJSON: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"PAN-SA-2025-0003": {
					CveID:       "PAN-SA-2025-0003",
					Confidences: models.Confidences{models.PaloaltoExactVersionMatch},
					CpeURIs:     []string{"cpe:/o:paloaltonetworks:pan-os:10.0.0", "cpe:2.3:o:paloaltonetworks:pan-os:10.0.0:*:*:*:*:*:*:*"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "PAN-SA-2025-0003",
							// Severity intentionally empty: Palo Alto carries CVSS, not a vendor SIR.
							Issued:      time.Date(2025, 1, 23, 23, 20, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
							Description: "Palo Alto Networks is aware of claims of multiple vulnerabilities in PA-Series firewall firmware and bootloaders.",
						},
					},
					CveContents: models.CveContents{
						models.Paloalto: []models.CveContent{
							{
								Type:       models.Paloalto,
								CveID:      "PAN-SA-2025-0003",
								Summary:    "Palo Alto Networks is aware of claims of multiple vulnerabilities in PA-Series firewall firmware and bootloaders.",
								SourceLink: "https://security.paloaltonetworks.com/PAN-SA-2025-0003",
								References: models.References{
									{
										Link:   "https://security.paloaltonetworks.com/PAN-SA-2025-0003",
										Source: "PALOALTO",
										RefID:  "PAN-SA-2025-0003",
									},
								},
								Published:    time.Date(2025, 1, 23, 23, 20, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"PAN-SA-2025-0003\",\"source_id\":\"paloalto-json\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// Fortinet is advisory-shaped (root = the FG-IR PSIRT advisory). The
			// CSAF extractor puts rich content (CVSS, CWE, refs) on the
			// vulnerability stub, so the generic path builds a full Fortinet
			// CveContent whose source link points at the PSIRT advisory page
			// (keyed by the root ID). The advisory itself carries no vendor SIR
			// (Fortinet severity is CVSS), so DistroAdvisory.Severity is empty.
			name: "cpe fortinet (csaf) detection emits CveContent (psirt source link) + DistroAdvisory",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:fortinet:fortipam:1.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:fortinet:fortipam:1.0.0:*:*:*:*:*:*:*": {"cpe:/a:fortinet:fortipam:1.0.0", "cpe:2.3:a:fortinet:fortipam:1.0.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "FG-IR-24-041",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FG-IR-24-041",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.FortinetCSAF: {
											dataTypes.RootID("FG-IR-24-041"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:        "FG-IR-24-041",
														Title:     "FGFM protocol allows unauthenticated reset of the connection",
														Published: new(time.Date(2025, 10, 14, 0, 0, 0, 0, time.UTC)),
														Modified:  new(time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2024-26008",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.FortinetCSAF: {
											dataTypes.RootID("FG-IR-24-041"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2024-26008",
														Title:       "FGFM protocol allows unauthenticated reset of the connection",
														Description: "Improper check or handling of exceptional conditions vulnerability in FortiOS, FortiProxy, FortiPAM & FortiSwitchManager",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "fortiguard.fortinet.com",
																Vendor: new("Denial of service"),
															},
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "fortiguard.fortinet.com",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:X/RC:C",
																	BaseScore:             5.3,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         5,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    5,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														CWE: []cweTypes.CWE{
															{
																Source: "fortiguard.fortinet.com",
																CWE:    []string{"CWE-754"},
															},
														},
														References: []referenceTypes.Reference{
															{
																Source: "fortiguard.fortinet.com",
																URL:    "https://fortiguard.fortinet.com/psirt/FG-IR-24-041",
															},
														},
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.FortinetCSAF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:fortinet:fortipam:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:         ccRangeTypes.RangeTypeFortinetFortiPAM,
																		GreaterEqual: "1.0",
																		LessThan:     "1.1",
																	}),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-26008": {
					CveID:       "CVE-2024-26008",
					Confidences: models.Confidences{models.FortinetExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:fortinet:fortipam:1.0.0", "cpe:2.3:a:fortinet:fortipam:1.0.0:*:*:*:*:*:*:*"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "FG-IR-24-041",
							// Severity empty: Fortinet advisory severity is CVSS, not a vendor SIR.
							Issued:  time.Date(2025, 10, 14, 0, 0, 0, 0, time.UTC),
							Updated: time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Fortinet: []models.CveContent{
							{
								Type:          models.Fortinet,
								CveID:         "CVE-2024-26008",
								Title:         "FGFM protocol allows unauthenticated reset of the connection",
								Summary:       "Improper check or handling of exceptional conditions vulnerability in FortiOS, FortiProxy, FortiPAM & FortiSwitchManager",
								Cvss3Score:    5.3,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L/E:P/RL:X/RC:C",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://www.fortiguard.com/psirt/FG-IR-24-041",
								References: models.References{
									{
										Link:   "https://fortiguard.fortinet.com/psirt/FG-IR-24-041",
										Source: "MISC",
									},
									{
										Link:   "https://www.fortiguard.com/psirt/FG-IR-24-041",
										Source: "FORTINET",
										RefID:  "FG-IR-24-041",
									},
								},
								CweIDs:       []string{"CWE-754"},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FG-IR-24-041\",\"source_id\":\"fortinet-csaf\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// Fortinet CVRF roots carry a BARE vulnerability stub (CVE-ID only),
			// so the generic path builds a sparse CveContent (no CVSS/title/
			// summary) whose source link still points at the PSIRT advisory
			// (root ID). The rich data lives in the advisory -> DistroAdvisory.
			// The advisory severity is CVSS (not a vendor SIR) so
			// DistroAdvisory.Severity stays empty.
			name: "cpe fortinet (cvrf) detection emits sparse CveContent + DistroAdvisory",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*": {"cpe:/a:fortinet:fortiportal:7.4.0", "cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "FG-IR-25-032",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FG-IR-25-032",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.FortinetCVRF: {
											dataTypes.RootID("FG-IR-25-032"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "FG-IR-25-032",
														Title:       "Incorrect authorization in multi-vdom environment",
														Description: "An Incorrect Authorization vulnerability [CWE-863] in FortiPortal may allow an authenticated attacker to reboot a shared FortiGate device via crafted HTTP requests.",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "fortiguard.fortinet.com",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
																	BaseScore:             6.8,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         6.4,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    6.4,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														Published: new(time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC)),
														Modified:  new(time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-54838",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.FortinetCVRF: {
											dataTypes.RootID("FG-IR-25-032"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2025-54838",
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.FortinetCVRF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"),
																	CPEMatches: []ccTypes.CPE{
																		"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*",
																		"cpe:2.3:a:fortinet:fortiportal:7.4.5:*:*:*:*:*:*:*",
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-54838": {
					CveID:       "CVE-2025-54838",
					Confidences: models.Confidences{models.FortinetExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:fortinet:fortiportal:7.4.0", "cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "FG-IR-25-032",
							// Severity empty: Fortinet advisory severity is CVSS, not a vendor SIR.
							Issued:      time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC),
							Description: "An Incorrect Authorization vulnerability [CWE-863] in FortiPortal may allow an authenticated attacker to reboot a shared FortiGate device via crafted HTTP requests.",
						},
					},
					CveContents: models.CveContents{
						models.Fortinet: []models.CveContent{
							{
								Type:       models.Fortinet,
								CveID:      "CVE-2025-54838",
								SourceLink: "https://www.fortiguard.com/psirt/FG-IR-25-032",
								References: models.References{
									{
										Link:   "https://www.fortiguard.com/psirt/FG-IR-25-032",
										Source: "FORTINET",
										RefID:  "FG-IR-25-032",
									},
								},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FG-IR-25-032\",\"source_id\":\"fortinet-cvrf\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// The same FG-IR advisory / CVE is present in BOTH Fortinet sources
			// (csaf rich stub, cvrf bare stub). They detect independently and
			// merge: csaf is preferred (compareSourceID tier 5 > cvrf tier 4), so
			// the merged Fortinet CveContent takes csaf's scalars (title/summary/
			// CVSS) and the DistroAdvisory takes csaf's (later Updated). The
			// vuls2-sources provenance lists both sources.
			name: "cpe fortinet csaf+cvrf both detect same CVE -> csaf preferred",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*": {"cpe:/a:fortinet:fortiportal:7.4.0", "cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "FG-IR-25-032",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FG-IR-25-032",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.FortinetCSAF: {
											dataTypes.RootID("FG-IR-25-032"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:        "FG-IR-25-032",
														Title:     "Incorrect authorization in multi-vdom environment",
														Published: new(time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC)),
														Modified:  new(time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
										sourceTypes.FortinetCVRF: {
											dataTypes.RootID("FG-IR-25-032"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "FG-IR-25-032",
														Title:       "Incorrect authorization in multi-vdom environment",
														Description: "An Incorrect Authorization vulnerability [CWE-863] in FortiPortal may allow an authenticated attacker to reboot a shared FortiGate device via crafted HTTP requests.",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "fortiguard.fortinet.com",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
																	BaseScore:             6.8,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         6.4,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    6.4,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														Published: new(time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC)),
														Modified:  new(time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-54838",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.FortinetCSAF: {
											dataTypes.RootID("FG-IR-25-032"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-54838",
														Title:       "Incorrect authorization in multi-vdom environment",
														Description: "Incorrect authorization in rebooting FortiGate device feature",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeVendor,
																Source: "fortiguard.fortinet.com",
																Vendor: new("Denial of service"),
															},
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "fortiguard.fortinet.com",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
																	BaseScore:             6.8,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         6.4,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    6.4,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														CWE: []cweTypes.CWE{
															{Source: "fortiguard.fortinet.com", CWE: []string{"CWE-863"}},
														},
														References: []referenceTypes.Reference{
															{Source: "fortiguard.fortinet.com", URL: "https://fortiguard.fortinet.com/psirt/FG-IR-25-032"},
														},
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
										sourceTypes.FortinetCVRF: {
											dataTypes.RootID("FG-IR-25-032"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID: "CVE-2025-54838",
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.FortinetCSAF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:         ccRangeTypes.RangeTypeFortinetFortiPortal,
																		GreaterEqual: "7.4.0",
																		LessEqual:    "7.4.5",
																	}),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
														},
													},
												},
											},
										},
										sourceTypes.FortinetCVRF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus:  new(vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassUnknown}),
																	CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"),
																	CPEMatches: []ccTypes.CPE{
																		"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*",
																	},
																}),
															},
															Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-54838": {
					CveID:       "CVE-2025-54838",
					Confidences: models.Confidences{models.FortinetExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:fortinet:fortiportal:7.4.0", "cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "FG-IR-25-032",
							Issued:     time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Fortinet: []models.CveContent{
							{
								Type:          models.Fortinet,
								CveID:         "CVE-2025-54838",
								Title:         "Incorrect authorization in multi-vdom environment",
								Summary:       "Incorrect authorization in rebooting FortiGate device feature",
								Cvss3Score:    6.8,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://www.fortiguard.com/psirt/FG-IR-25-032",
								References: models.References{
									{Link: "https://fortiguard.fortinet.com/psirt/FG-IR-25-032", Source: "MISC"},
									{Link: "https://www.fortiguard.com/psirt/FG-IR-25-032", Source: "FORTINET", RefID: "FG-IR-25-032"},
								},
								CweIDs:       []string{"CWE-863"},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FG-IR-25-032\",\"source_id\":\"fortinet-cvrf\",\"segment\":{\"ecosystem\":\"cpe\"}},{\"root_id\":\"FG-IR-25-032\",\"source_id\":\"fortinet-csaf\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// A CVE detected by BOTH NVD (feed v2) and Fortinet CSAF must keep
			// BOTH CveContents in the result — they are different CveContentTypes
			// (models.Nvd vs models.Fortinet), so the merge keys them separately
			// and neither overwrites the other.
			name: "cpe nvd-v2 + fortinet-csaf both detect same CVE -> both CveContents kept",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*": {"cpe:/a:fortinet:fortiportal:7.4.0", "cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-54838",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-54838",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDFeedCVEv2: {
											dataTypes.RootID("CVE-2025-54838"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-54838",
														Title:       "Fortinet FortiPortal incorrect authorization",
														Description: "NVD-side description for CVE-2025-54838",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "nvd@nist.gov",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
																	BaseScore:             6.8,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         6.4,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    6.4,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{Source: "nvd@nist.gov", URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-54838"},
														},
														Published: new(time.Date(2025, 12, 10, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDFeedCVEv2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:         ccRangeTypes.RangeTypeSEMVER,
																		GreaterEqual: "7.4.0",
																		LessEqual:    "7.4.5",
																	}),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							ID: "FG-IR-25-032",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "FG-IR-25-032",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.FortinetCSAF: {
											dataTypes.RootID("FG-IR-25-032"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:        "FG-IR-25-032",
														Title:     "Incorrect authorization in multi-vdom environment",
														Published: new(time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC)),
														Modified:  new(time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-54838",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.FortinetCSAF: {
											dataTypes.RootID("FG-IR-25-032"): []vulnerabilityTypes.Vulnerability{
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-54838",
														Title:       "Incorrect authorization in multi-vdom environment",
														Description: "Incorrect authorization in rebooting FortiGate device feature",
														Severity: []severityTypes.Severity{
															{
																Type:   severityTypes.SeverityTypeCVSSv31,
																Source: "fortiguard.fortinet.com",
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:                "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
																	BaseScore:             6.8,
																	BaseSeverity:          "MEDIUM",
																	TemporalScore:         6.4,
																	TemporalSeverity:      "MEDIUM",
																	EnvironmentalScore:    6.4,
																	EnvironmentalSeverity: "MEDIUM",
																}),
															},
														},
														CWE: []cweTypes.CWE{
															{Source: "fortiguard.fortinet.com", CWE: []string{"CWE-863"}},
														},
														References: []referenceTypes.Reference{
															{Source: "fortiguard.fortinet.com", URL: "https://fortiguard.fortinet.com/psirt/FG-IR-25-032"},
														},
													},
													Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE}},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.FortinetCSAF: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:fortinet:fortiportal:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:         ccRangeTypes.RangeTypeFortinetFortiPortal,
																		GreaterEqual: "7.4.0",
																		LessEqual:    "7.4.5",
																	}),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{CPE: criterionTypes.CPEAccepts{Exact: []int{0}}},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-54838": {
					CveID:       "CVE-2025-54838",
					Confidences: models.Confidences{models.NvdExactVersionMatch, models.FortinetExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:fortinet:fortiportal:7.4.0", "cpe:2.3:a:fortinet:fortiportal:7.4.0:*:*:*:*:*:*:*"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID: "FG-IR-25-032",
							Issued:     time.Date(2025, 12, 9, 0, 0, 0, 0, time.UTC),
							Updated:    time.Date(2026, 1, 14, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:          models.Nvd,
								CveID:         "CVE-2025-54838",
								Title:         "Fortinet FortiPortal incorrect authorization",
								Summary:       "NVD-side description for CVE-2025-54838",
								Cvss3Score:    6.8,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-2025-54838",
								References: models.References{
									{Link: "https://nvd.nist.gov/vuln/detail/CVE-2025-54838", Source: "NVD", RefID: "CVE-2025-54838"},
								},
								Published:    time.Date(2025, 12, 10, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-54838\",\"source_id\":\"nvd-feed-cve-v2\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
						models.Fortinet: []models.CveContent{
							{
								Type:          models.Fortinet,
								CveID:         "CVE-2025-54838",
								Title:         "Incorrect authorization in multi-vdom environment",
								Summary:       "Incorrect authorization in rebooting FortiGate device feature",
								Cvss3Score:    6.8,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H/E:P/RL:X/RC:C",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://www.fortiguard.com/psirt/FG-IR-25-032",
								References: models.References{
									{Link: "https://fortiguard.fortinet.com/psirt/FG-IR-25-032", Source: "MISC"},
									{Link: "https://www.fortiguard.com/psirt/FG-IR-25-032", Source: "FORTINET", RefID: "FG-IR-25-032"},
								},
								CweIDs:       []string{"CWE-863"},
								Published:    time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"FG-IR-25-032\",\"source_id\":\"fortinet-csaf\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// A criterion accepted the query only at version-unconfirmed
			// quality (the upstream matcher could not confirm the scanned
			// version is affected), so the CVE is reported with the low
			// NvdVendorProductMatch confidence. Criterions that did not accept
			// — different vendor:product, vulnerable=false hardware guards, or
			// a range the query fell outside — carry empty Accepts and do not
			// contribute.
			name: "cpe version-unconfirmed accept -> vendor:product",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:9.9.9"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0003",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0003",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0003"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0003",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://nvd.nist.gov/vuln/detail/CVE-2025-0003",
															},
														},
														Published: new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// accepted at version-unconfirmed quality -> vendor:product
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{VersionUnconfirmed: []int{0}},
															},
														},
														{
															// same vendor:product but the range confirms the
															// scanned 9.9.9 is out of range -> no contribution
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:     ccRangeTypes.RangeTypeSEMVER,
																		LessThan: "5.0",
																	}),
																}),
															},
														},
														{
															// different vendor:product -> no contribution
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:othervendor:otherproduct:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
														},
														{
															// vulnerable=false (hardware guard) -> excluded
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: false,
																	CPE:        ccTypes.CPE("cpe:2.3:h:vendor:product:-:*:*:*:*:*:*:*"),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0003": {
					CveID:       "CVE-2025-0003",
					Confidences: models.Confidences{models.NvdVendorProductMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:9.9.9"},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:       models.Nvd,
								CveID:      "CVE-2025-0003",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-2025-0003",
								References: models.References{
									{
										Link:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0003",
										Source: "NVD",
										RefID:  "CVE-2025-0003",
									},
								},
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0003\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// Projection honours AND structure: a CVE whose configuration
			// requires product A AND product B is not reported when only A was
			// scanned (A's leg accepted, but B's leg did not).
			name: "cpe version-unconfirmed accept, unsatisfied AND",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:producta:9.9.9"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0004",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeAND,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:producta:-:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{VersionUnconfirmed: []int{0}},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:productb:-:*:*:*:*:*:*:*"),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			// The detection reached us via the part:vendor:product index, but
			// no criterion accepted (every one carries empty Accepts — concrete
			// version mismatch, out of range, enumeration miss upstream). The
			// condition yields no signal, so it is not registered at all —
			// without that gate the CVE's content would be emitted for an
			// undetected CVE.
			name: "cpe no accepted criterion, report nothing",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:9.9.9"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0007",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0007",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0007"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0007",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															// concrete version differing from the scanned one
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
																}),
															},
														},
														{
															// range that confirms 9.9.9 is out of range
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:     ccRangeTypes.RangeTypeSEMVER,
																		LessThan: "5.0",
																	}),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			// Both AND legs accept at version-unconfirmed quality with both
			// products scanned: the conjunction is satisfied and reports both
			// CPEs at VendorProductMatch.
			name: "cpe version-unconfirmed accept, satisfied AND",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*",
						"cpe:2.3:a:vendor:productb:8.8.8:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:producta:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:producta:9.9.9"},
					"cpe:2.3:a:vendor:productb:8.8.8:*:*:*:*:*:*:*": {"cpe:/a:vendor:productb:8.8.8"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0004",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0004",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0004"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0004",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeAND,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:producta:-:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{VersionUnconfirmed: []int{0}},
															},
														},
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:productb:-:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{VersionUnconfirmed: []int{1}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0004": {
					CveID:       "CVE-2025-0004",
					Confidences: models.Confidences{models.NvdVendorProductMatch},
					CpeURIs:     []string{"cpe:/a:vendor:producta:9.9.9", "cpe:/a:vendor:productb:8.8.8"},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:         models.Nvd,
								CveID:        "CVE-2025-0004",
								Title:        "title",
								Summary:      "description",
								SourceLink:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0004",
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0004\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// An NVD criterion with version=* and no Range / CPEMatches
			// states every version is affected, so it is a real exact
			// match (NvdExactVersionMatch), not vendor:product.
			name: "cpe version=* criterion accept -> ExactVersionMatch",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:9.9.9"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0006",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0006",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0006"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0006",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-0006": {
					CveID:       "CVE-2025-0006",
					Confidences: models.Confidences{models.NvdExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:9.9.9"},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:         models.Nvd,
								CveID:        "CVE-2025-0006",
								Title:        "title",
								Summary:      "description",
								SourceLink:   "https://nvd.nist.gov/vuln/detail/CVE-2025-0006",
								Published:    time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2025-0006\",\"source_id\":\"nvd-api-cve\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// The scanned version (21.4r3, the juniper joined form) cannot be
			// compared by the range's semver comparator and is not in the
			// criterion's CPEMatches, so it is not detected — the RPM
			// fallback (which only produced the retired RoughVersionMatch) is
			// gone. A detect-side query normalizer that splits the joined form
			// into version "21.4" / update "r3" is the intended fix; the
			// well-formed query would match "21.4 < 22.2" at Exact instead.
			name: "cpe non-semver query against a range -> not detected",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:o:vendor:product:21.4r3:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:o:vendor:product:21.4r3:*:*:*:*:*:*:*": {"cpe:/o:vendor:product:21.4r3"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2025-0005",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2025-0005",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2025-0005"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2025-0005",
														Title:       "title",
														Description: "description",
														Published:   new(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*"),
																	Range: new(ccRangeTypes.Range{
																		Type:     ccRangeTypes.RangeTypeSEMVER,
																		LessThan: "22.2",
																	}),
																}),
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			// VulnCheck under the CPE ecosystem mirrors NVD detection: an
			// exact accept yields models.VulncheckExactVersionMatch and a
			// models.Vulncheck CveContent whose SourceLink is the VulnCheck
			// console URL. (No verified source defines this product, so the
			// verified-product suppression in walkCPECriteria does not apply.)
			name: "cpe vulncheck exact accept -> Vulncheck content",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:0.0.0"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "CVE-2024-3401",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2024-3401",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.VulnCheckNISTNVD2: {
											dataTypes.RootID("CVE-2024-3401"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2024-3401",
														Title:       "title",
														Description: "description",
														Severity: []severityTypes.Severity{
															{
																Type: severityTypes.SeverityTypeCVSSv31,
																CVSSv31: new(cvssV31Types.CVSSv31{
																	Vector:       "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
																	BaseScore:    9.8,
																	BaseSeverity: "CRITICAL",
																}),
															},
														},
														References: []referenceTypes.Reference{
															{
																URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-3401",
															},
														},
														Published: new(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.VulnCheckNISTNVD2: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-3401": {
					CveID:       "CVE-2024-3401",
					Confidences: models.Confidences{models.VulncheckExactVersionMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:0.0.0"},
					CveContents: models.CveContents{
						models.Vulncheck: []models.CveContent{
							{
								Type:          models.Vulncheck,
								CveID:         "CVE-2024-3401",
								Title:         "title",
								Summary:       "description",
								Cvss3Score:    9.8,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
								Cvss3Severity: "CRITICAL",
								SourceLink:    "https://console.vulncheck.com/cve/CVE-2024-3401",
								References: models.References{
									{
										Link:   "https://nvd.nist.gov/vuln/detail/CVE-2024-3401",
										Source: "NVD",
										RefID:  "CVE-2024-3401",
									},
								},
								Published:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"CVE-2024-3401\",\"source_id\":\"vulncheck-nist-nvd2\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// JVN's CPE entries carry no version data, so walkCPECriteria
			// demotes even an exact accept to the vendor:product tier
			// (isJVNCPESource): the CVE is reported with
			// models.JvnVendorProductMatch. The CPE detection path yields a
			// sparse models.Jvn CveContent whose SourceLink is the JVNDB
			// advisory URL (cveContentSourceLink's JVN case); enrichJVN keeps
			// this entry, only adding a bare source-link pointer for JVNDB
			// notes not already present, so the detection-built content is
			// preserved. The advisory content under the same root becomes a
			// DistroAdvisory (AdvisoryID = JVNDB ID) and its jvndb.jvn.jp
			// reference is folded into the content.
			name: "cpe jvn exact accept -> demoted vendor:product + DistroAdvisory",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:0.0.0"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "JVNDB-2024-000456",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "CVE-2024-30001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "JVNDB-2024-000456",
														Title:       "advisory title",
														Description: "advisory description",
														Published:   new(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2024-30001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2024-30001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://jvn.jp/vu/JVNVU90009999/index.html",
															},
														},
														Published: new(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.JVNFeedRSS: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-30001": {
					CveID:       "CVE-2024-30001",
					Confidences: models.Confidences{models.JvnVendorProductMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:0.0.0"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "JVNDB-2024-000456",
							Description: "advisory description",
							Issued:      time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Jvn: []models.CveContent{
							{
								Type:       models.Jvn,
								CveID:      "CVE-2024-30001",
								Title:      "title",
								Summary:    "description",
								SourceLink: "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000456.html",
								References: models.References{
									{
										Link:   "https://jvn.jp/vu/JVNVU90009999/index.html",
										Source: "MISC",
									},
									{
										Link:   "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000456.html",
										Source: "JVN",
										RefID:  "JVNDB-2024-000456",
									},
								},
								Published:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"JVNDB-2024-000456\",\"source_id\":\"jvn-feed-rss\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
		{
			// Same JVN detection as the case above, but the scanned CPE is
			// marked UseJVN:false (in noJVNCPEs). walkCPECriteria's suppress()
			// drops the match for JVN sources, so — with no other source — the
			// CVE disappears from the result entirely. Locks the noJVNCPEs
			// wiring through postConvert (its per-CPE behaviour is unit-tested
			// in Test_walkCPECriteria).
			name: "cpe jvn exact accept but CPE in noJVNCPEs -> suppressed, no VulnInfo",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:0.0.0"},
				},
				noJVNCPEs: map[string]struct{}{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							ID: "JVNDB-2024-000456",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "CVE-2024-30001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "JVNDB-2024-000456",
														Title:       "advisory title",
														Description: "advisory description",
														Published:   new(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2024-30001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2024-30001",
														Title:       "title",
														Description: "description",
														References: []referenceTypes.Reference{
															{
																URL: "https://jvn.jp/vu/JVNVU90009999/index.html",
															},
														},
														Published: new(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.JVNFeedRSS: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{},
		},
		{
			// A multi-CVE JVN root: one advisory and one CPE detection block
			// shared by CVE-2024-30001 and CVE-2024-30002. A verified source
			// defines a:vendor:product only for CVE-2024-30001, so the per-CVE
			// walk suppresses the scanned CPE for that CVE alone — CVE-2024-30001
			// drops out entirely while its sibling CVE-2024-30002 still detects
			// (demoted to vendor:product, with the shared DistroAdvisory).
			name: "cpe jvn multi-CVE root: verified product suppresses only its own CVE, not the sibling",
			args: args{
				scanned: scanTypes.ScanResult{
					CPE: []string{
						"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*",
					},
				},
				fsToOriginalCPE: map[string][]string{
					"cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*": {"cpe:/a:vendor:product:0.0.0"},
				},
				detected: detectTypes.DetectResult{
					Detected: []detectTypes.VulnerabilityData{
						{
							// Verified (NVD) root defining a:vendor:product for
							// CVE-2024-30001 only. Its CPE is unmatched (empty
							// Accepts) so it yields no VulnInfo of its own, but
							// collectVerifiedProducts still derives the product,
							// which suppresses JVN's CVE-2024-30001 match.
							ID: "CVE-2024-30001",
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2024-30001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.NVDAPICVE: {
											dataTypes.RootID("CVE-2024-30001"): {
												{
													Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-30001"},
													Segments: []segmentTypes.Segment{
														{Ecosystem: ecosystemTypes.EcosystemTypeCPE},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.NVDAPICVE: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	CPE:        ccTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
																}),
															},
															// Empty Accepts: unmatched by the scan.
															Accepts: criterionTypes.AcceptQueries{},
														},
													},
												},
											},
										},
									},
								},
							},
						},
						{
							ID: "JVNDB-2024-000456",
							Advisories: []dbTypes.VulnerabilityDataAdvisory{
								{
									ID: "JVNDB-2024-000456",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): []advisoryTypes.Advisory{
												{
													Content: advisoryContentTypes.Content{
														ID:          "JVNDB-2024-000456",
														Title:       "advisory title",
														Description: "advisory description",
														Published:   new(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
								{
									ID: "CVE-2024-30001",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2024-30001",
														Title:       "title 30001",
														Description: "description 30001",
														References: []referenceTypes.Reference{
															{
																URL: "https://jvn.jp/vu/JVNVU90009999/index.html",
															},
														},
														Published: new(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
								{
									ID: "CVE-2024-30002",
									Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
										sourceTypes.JVNFeedRSS: {
											dataTypes.RootID("JVNDB-2024-000456"): {
												{
													Content: vulnerabilityContentTypes.Content{
														ID:          "CVE-2024-30002",
														Title:       "title 30002",
														Description: "description 30002",
														References: []referenceTypes.Reference{
															{
																URL: "https://jvn.jp/vu/JVNVU90009999/index.html",
															},
														},
														Published: new(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)),
													},
													Segments: []segmentTypes.Segment{
														{
															Ecosystem: ecosystemTypes.EcosystemTypeCPE,
														},
													},
												},
											},
										},
									},
								},
							},
							Detections: []detectTypes.VulnerabilityDataDetection{
								{
									Ecosystem: ecosystemTypes.EcosystemTypeCPE,
									Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
										sourceTypes.JVNFeedRSS: {
											{
												Criteria: criteriaTypes.FilteredCriteria{
													Operator: criteriaTypes.CriteriaOperatorTypeOR,
													Criterions: []criterionTypes.FilteredCriterion{
														{
															Criterion: criterionTypes.Criterion{
																Type: criterionTypes.CriterionTypeCPE,
																CPE: new(ccTypes.Criterion{
																	Vulnerable: true,
																	FixStatus: new(vcFixStatusTypes.FixStatus{
																		Class: vcFixStatusTypes.ClassUnknown,
																	}),
																	CPE: ccTypes.CPE("cpe:2.3:a:vendor:product:0.0.0:*:*:*:*:*:*:*"),
																}),
															},
															Accepts: criterionTypes.AcceptQueries{
																CPE: criterionTypes.CPEAccepts{Exact: []int{0}},
															},
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-30002": {
					CveID:       "CVE-2024-30002",
					Confidences: models.Confidences{models.JvnVendorProductMatch},
					CpeURIs:     []string{"cpe:/a:vendor:product:0.0.0"},
					DistroAdvisories: models.DistroAdvisories{
						{
							AdvisoryID:  "JVNDB-2024-000456",
							Description: "advisory description",
							Issued:      time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC),
							Updated:     time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
						},
					},
					CveContents: models.CveContents{
						models.Jvn: []models.CveContent{
							{
								Type:       models.Jvn,
								CveID:      "CVE-2024-30002",
								Title:      "title 30002",
								Summary:    "description 30002",
								SourceLink: "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000456.html",
								References: models.References{
									{
										Link:   "https://jvn.jp/vu/JVNVU90009999/index.html",
										Source: "MISC",
									},
									{
										Link:   "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000456.html",
										Source: "JVN",
										RefID:  "JVNDB-2024-000456",
									},
								},
								Published:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, time.January, 1, 0, 0, 0, 0, time.UTC),
								Optional: map[string]string{
									"vuls2-sources": "[{\"root_id\":\"JVNDB-2024-000456\",\"source_id\":\"jvn-feed-rss\",\"segment\":{\"ecosystem\":\"cpe\"}}]",
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PostConvert(tt.args.scanned, tt.args.detected, tt.args.fsToOriginalCPE, tt.args.noJVNCPEs)
			if (err != nil) != tt.wantErr {
				t.Errorf("postConvert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff, err := compareVulnInfos(got, tt.want)
			if err != nil {
				t.Errorf("postConvert() compareVulnInfos() error = %v", err)
				return
			}
			if diff != "" {
				t.Errorf("postConvert() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_prunePkgCriteria(t *testing.T) {
	type args struct {
		criteria criteriaTypes.FilteredCriteria
	}
	tests := []struct {
		name    string
		args    args
		want    criteriaTypes.FilteredCriteria
		wantErr bool
	}{
		{
			name: "criterion with accepts, kept as is",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-1",
										},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{
								Version: []int{1},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versioncriterionTypes.Criterion{
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "pkg-1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{
							Version: []int{1},
						},
					},
				},
			},
		},
		{
			name: "criterions without accepts, vanishes in whole",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-1",
										},
									},
								},
							},
						},
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-2",
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:   criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{},
			},
		},
		{
			name: "criterions with and without accepts, partially kept",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-1",
										},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{
								Version: []int{1},
							},
						},
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &versioncriterionTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "pkg-2",
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versioncriterionTypes.Criterion{
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "pkg-1",
									},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{
							Version: []int{1},
						},
					},
				},
			},
		},
		{
			name: "AND-criteria, one criterion has accepts but another does not, vanishes in whole",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-1",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{1},
									},
								},
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-2",
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:  criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{},
			},
		},
		{
			name: "AND-criterias evaluated to true and false, kept partially",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-1",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{1},
									},
								},
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-2",
												},
											},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-3",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{3},
									},
								},
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &versioncriterionTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type: vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{
													Name: "pkg-4",
												},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{
										Version: []int{4},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &versioncriterionTypes.Criterion{
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "pkg-3",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{
									Version: []int{3},
								},
							},
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &versioncriterionTypes.Criterion{
										Package: vcPackageTypes.Package{
											Type: vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{
												Name: "pkg-4",
											},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{
									Version: []int{4},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "AND-criterias with true and false criterias in children, kept partially",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-1",
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: []int{1},
											},
										},
									},
								},
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-2",
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: []int{2},
											},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-3",
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{
												Version: []int{3},
											},
										},
									},
								},
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &versioncriterionTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "pkg-4",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &versioncriterionTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "pkg-1",
													},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{
											Version: []int{1},
										},
									},
								},
							},
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &versioncriterionTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "pkg-2",
													},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{
											Version: []int{2},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PrunePkgCriteria(tt.args.criteria)
			if (err != nil) != tt.wantErr {
				t.Errorf("prunePkgCriteria() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := gocmp.Diff(got, tt.want); diff != "" {
				t.Errorf("prunePkgCriteria() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_mergeIntoScannedCves(t *testing.T) {
	verified := true
	type args struct {
		r         models.ScanResult
		vulnInfos models.VulnInfos
	}
	tests := []struct {
		name string
		args args
		want models.VulnInfos
	}{
		{
			// A zero-value ScanResult from a library consumer carries a nil
			// ScannedCves map; the merge initializes it instead of
			// panicking on assignment.
			name: "nil ScannedCves map is initialized",
			args: args{
				r: models.ScanResult{},
				vulnInfos: models.VulnInfos{
					"CVE-2025-1000": {
						CveID:       "CVE-2025-1000",
						Confidences: models.Confidences{models.NvdExactVersionMatch},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-1000": {
					CveID:       "CVE-2025-1000",
					Confidences: models.Confidences{models.NvdExactVersionMatch},
				},
			},
		},
		{
			name: "new CVE is registered as-is",
			args: args{
				r: models.ScanResult{ScannedCves: models.VulnInfos{}},
				vulnInfos: models.VulnInfos{
					"CVE-2025-1001": {
						CveID:             "CVE-2025-1001",
						Confidences:       models.Confidences{models.NvdExactVersionMatch},
						CpeURIs:           []string{"cpe:/a:vendor:product:1.0"},
						WindowsKBFixedIns: []string{"KB5000001"},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2025-1001": {
					CveID:             "CVE-2025-1001",
					Confidences:       models.Confidences{models.NvdExactVersionMatch},
					CpeURIs:           []string{"cpe:/a:vendor:product:1.0"},
					WindowsKBFixedIns: []string{"KB5000001"},
				},
			},
		},
		{
			// Every field the vuls2 postConvert produces merges into a CVE
			// that another pass registered first: KB numbers and packages
			// append (KB dedups), advisories / confidences / exploits /
			// mitigations append-if-missing, CveContents starts from a nil
			// map (a result JSON with cveContents omitted), and CpeURIs
			// dedups against the go-cve-dictionary pass.
			name: "merge into an already-registered CVE",
			args: args{
				r: models.ScanResult{ScannedCves: models.VulnInfos{
					"CVE-2025-1002": {
						CveID:             "CVE-2025-1002",
						Confidences:       models.Confidences{models.JvnVendorProductMatch},
						CpeURIs:           []string{"cpe:/a:vendor:product:1.0"},
						WindowsKBFixedIns: []string{"KB5000001"},
						DistroAdvisories:  models.DistroAdvisories{{AdvisoryID: "JVNDB-2025-000001"}},
						Exploits:          models.Exploits{{ExploitType: models.ExploitTypeNVD, URL: "https://example.com/exploit"}},
						Mitigations:       models.Mitigations{{CveContentType: models.Nvd, URL: "https://example.com/mitigation"}},
						CveContents:       nil,
					},
				}},
				vulnInfos: models.VulnInfos{
					"CVE-2025-1002": {
						CveID:             "CVE-2025-1002",
						Confidences:       models.Confidences{models.NvdExactVersionMatch},
						AffectedPackages:  models.PackageFixStatuses{{Name: "package1", FixedIn: "1.1"}},
						CpeURIs:           []string{"cpe:/a:vendor:product:1.0", "cpe:/a:vendor:product:2.0"},
						WindowsKBFixedIns: []string{"KB5000001", "KB5000002"},
						DistroAdvisories:  models.DistroAdvisories{{AdvisoryID: "KB5000002", Description: "Microsoft Knowledge Base"}},
						Exploits:          models.Exploits{{ExploitType: models.ExploitTypeNVD, URL: "https://example.com/exploit", Verified: &verified}},
						Mitigations: models.Mitigations{
							{CveContentType: models.Nvd, URL: "https://example.com/mitigation"},
							{CveContentType: models.Nvd, URL: "https://example.com/mitigation2"},
						},
						CveContents: models.CveContents{
							models.Nvd: []models.CveContent{{Type: models.Nvd, CveID: "CVE-2025-1002"}},
						},
					},
				},
			},
			// AppendIfMissing keeps the first entry per natural key, so the
			// pre-existing exploit (no Verified) wins over the incoming
			// Verified duplicate.
			want: models.VulnInfos{
				"CVE-2025-1002": {
					CveID:             "CVE-2025-1002",
					Confidences:       models.Confidences{models.JvnVendorProductMatch, models.NvdExactVersionMatch},
					AffectedPackages:  models.PackageFixStatuses{{Name: "package1", FixedIn: "1.1"}},
					CpeURIs:           []string{"cpe:/a:vendor:product:1.0", "cpe:/a:vendor:product:2.0"},
					WindowsKBFixedIns: []string{"KB5000001", "KB5000002"},
					DistroAdvisories: models.DistroAdvisories{
						{AdvisoryID: "JVNDB-2025-000001"},
						{AdvisoryID: "KB5000002", Description: "Microsoft Knowledge Base"},
					},
					Exploits: models.Exploits{{ExploitType: models.ExploitTypeNVD, URL: "https://example.com/exploit"}},
					Mitigations: models.Mitigations{
						{CveContentType: models.Nvd, URL: "https://example.com/mitigation"},
						{CveContentType: models.Nvd, URL: "https://example.com/mitigation2"},
					},
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{{Type: models.Nvd, CveID: "CVE-2025-1002"}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.args.r
			vuls2.MergeIntoScannedCves(&r, tt.args.vulnInfos)
			if diff := gocmp.Diff(r.ScannedCves, tt.want); diff != "" {
				t.Errorf("mergeIntoScannedCves() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

// Test_walkCPECriteria covers the projection of a cpe-ecosystem condition onto
// vuls0's exact / vendor:product tiers. All CPE match-quality judgement now
// happens upstream (cpecriterion.Match -> AcceptQueries.CPE.Exact /
// VersionUnconfirmed); this function only folds those pre-classified indices
// up the AND/OR tree, applies the JVN source demotion, and de-duplicates with
// exact taking precedence over vendor:product for the same scanned CPE.
func Test_walkCPECriteria(t *testing.T) {
	// cpeCriterion builds a vulnerable CPE FilteredCriterion whose accepted
	// query indices are pre-classified by tier. The criterion CPE string is
	// irrelevant to projection (only the Vulnerable flag matters, for pruning).
	cpeCriterion := func(exact, versionUnconfirmed []int) criterionTypes.FilteredCriterion {
		return criterionTypes.FilteredCriterion{
			Criterion: criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: new(ccTypes.Criterion{
					Vulnerable: true,
					CPE:        ccTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
				}),
			},
			Accepts: criterionTypes.AcceptQueries{
				CPE: criterionTypes.CPEAccepts{Exact: exact, VersionUnconfirmed: versionUnconfirmed},
			},
		}
	}
	type args struct {
		sourceID         sourceTypes.SourceID
		criteria         criteriaTypes.FilteredCriteria
		scanned          []string
		noJVNCPEs        map[string]struct{}
		verifiedProducts map[string]struct{}
	}
	tests := []struct {
		name      string
		args      args
		wantExact []string
		wantVP    []string
	}{
		{
			name: "exact-quality index -> exact tier",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			name: "version-unconfirmed index -> vendor:product tier",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion(nil, []int{0})},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
			wantVP: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			name: "OR unions exact and vendor:product across legs",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion([]int{0}, nil),
						cpeCriterion(nil, []int{1}),
					},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
			wantVP:    []string{"cpe:2.3:a:vendor:other:2.0:*:*:*:*:*:*:*"},
		},
		{
			name: "AND of exact-only legs -> exact",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion([]int{0}, nil),
						cpeCriterion([]int{1}, nil),
					},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:o:vendor:os:2.0:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:o:vendor:os:2.0:*:*:*:*:*:*:*"},
		},
		{
			name: "AND with a vendor:product leg demotes the whole conjunction",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion([]int{0}, nil),
						cpeCriterion(nil, []int{1}),
					},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "cpe:2.3:o:vendor:os:2.0:*:*:*:*:*:*:*"},
			},
			wantVP: []string{"cpe:2.3:o:vendor:os:2.0:*:*:*:*:*:*:*", "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		{
			name: "AND with an unsatisfied leg -> nothing",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion([]int{0}, nil),
						cpeCriterion(nil, nil),
					},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
			},
		},
		{
			name: "same scanned CPE in exact and vendor:product -> exact wins",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion([]int{0}, nil),
						cpeCriterion(nil, []int{0}),
					},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"},
		},
		{
			name: "NVD source keeps exact",
			args: args{
				sourceID: sourceTypes.NVDFeedCVEv2,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			// JVN carries no version data, so even an exact-quality projection
			// only confirms part:vendor:product. This is a source-semantics
			// demotion that lives in vuls0, not in the source-agnostic matcher.
			name: "JVN source demotes exact to vendor:product",
			args: args{
				sourceID: sourceTypes.JVNFeedRSS,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
			wantVP: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			name: "vulnerable=false guard is pruned, sibling exact survives",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterions: []criterionTypes.FilteredCriterion{
						cpeCriterion([]int{0}, nil),
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeCPE,
								CPE: new(ccTypes.Criterion{
									Vulnerable: false,
									CPE:        ccTypes.CPE("cpe:2.3:h:vendor:hardware:-:*:*:*:*:*:*:*"),
								}),
							},
						},
					},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			name: "empty condition -> nothing",
			args: args{
				criteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
				scanned:  []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
		},
		{
			// A VulnCheck CPE match is projected like any other source when no
			// verified source defines its part:vendor:product for the CVE.
			name: "vulncheck kept when no verified product",
			args: args{
				sourceID: sourceTypes.VulnCheckNISTNVD2,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			// A VulnCheck match whose part:vendor:product is defined by a
			// verified source (NVD/Fortinet/Cisco/PaloAlto) detected for the CVE
			// is suppressed — go-cve-dictionary's behaviour. This is also how the
			// NVD-mirror half of VulnCheck's data is dropped, without inspecting
			// the source's criteria structure.
			name: "vulncheck suppressed by verified product",
			args: args{
				sourceID: sourceTypes.VulnCheckNISTNVD2,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:          []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				verifiedProducts: map[string]struct{}{"a:vendor:product": {}},
			},
		},
		{
			// JVN is suppressed by a verified product exactly like VulnCheck —
			// isSuppressedCPESource covers both suppressed CPE sources.
			name: "jvn suppressed by verified product",
			args: args{
				sourceID: sourceTypes.JVNFeedRSS,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:          []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				verifiedProducts: map[string]struct{}{"a:vendor:product": {}},
			},
		},
		{
			// Suppression is part:vendor:product-scoped: a verified product that
			// is not the matched CPE's product does not suppress it.
			name: "vulncheck not suppressed by unrelated verified product",
			args: args{
				sourceID: sourceTypes.VulnCheckNISTNVD2,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:          []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				verifiedProducts: map[string]struct{}{"a:other:thing": {}},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			// Verified-product suppression applies only to suppressed sources
			// (VulnCheck / JVN, see isSuppressedCPESource): a verified source
			// keeps its own match even when verifiedProducts contains that product.
			name: "verified source ignores verifiedProducts",
			args: args{
				sourceID: sourceTypes.NVDFeedCVEv2,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:          []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				verifiedProducts: map[string]struct{}{"a:vendor:product": {}},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			// A scanned CPE marked UseJVN:false (in noJVNCPEs) suppresses JVN-source
			// matches for it — the per-CPE "no JVN" policy (e.g. macOS Apple CPEs).
			name: "JVN suppressed for a no-JVN CPE",
			args: args{
				sourceID: sourceTypes.JVNFeedRSS,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:   []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				noJVNCPEs: map[string]struct{}{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*": {}},
			},
		},
		{
			// noJVNCPEs only gates JVN sources: a non-JVN source keeps its match
			// for the same scanned CPE.
			name: "no-JVN CPE does not affect a non-JVN source",
			args: args{
				sourceID: sourceTypes.NVDFeedCVEv2,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:   []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				noJVNCPEs: map[string]struct{}{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*": {}},
			},
			wantExact: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
		{
			// A JVN match for a CPE NOT in noJVNCPEs is kept (demoted to
			// vendor:product as usual), confirming the gate is per-CPE.
			name: "JVN kept for a CPE not marked no-JVN",
			args: args{
				sourceID: sourceTypes.JVNFeedRSS,
				criteria: criteriaTypes.FilteredCriteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{cpeCriterion([]int{0}, nil)},
				},
				scanned:   []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
				noJVNCPEs: map[string]struct{}{"cpe:2.3:a:other:thing:1.0:*:*:*:*:*:*:*": {}},
			},
			wantVP: []string{"cpe:2.3:a:vendor:product:9.9.9:*:*:*:*:*:*:*"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exact, vp, err := vuls2.WalkCPECriteria(tt.args.sourceID, tt.args.criteria, scanTypes.ScanResult{CPE: tt.args.scanned}, tt.args.noJVNCPEs, tt.args.verifiedProducts)
			if err != nil {
				t.Fatalf("walkCPECriteria() error = %v", err)
			}
			if diff := gocmp.Diff(exact, tt.wantExact); diff != "" {
				t.Errorf("exact mismatch (-got +want):\n%s", diff)
			}
			if diff := gocmp.Diff(vp, tt.wantVP); diff != "" {
				t.Errorf("vendor:product mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func Test_enrich(t *testing.T) {
	type args struct {
		vim models.VulnInfos
	}
	tests := []struct {
		name    string
		args    args
		want    models.VulnInfos
		wantErr bool
	}{
		{
			name: "enrich with redhat-cve data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-1102": models.VulnInfo{
						CveID: "CVE-2024-1102",
						CveContents: models.CveContents{
							models.RedHat: []models.CveContent{
								{
									Type:  models.RedHat,
									CveID: "CVE-2024-1102",
									Title: "from-oval",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-1102": models.VulnInfo{
					CveID: "CVE-2024-1102",
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:  models.RedHat,
								CveID: "CVE-2024-1102",
								Title: "from-oval",
							},
						},
						models.RedHatAPI: []models.CveContent{
							{
								Type:          models.RedHatAPI,
								CveID:         "CVE-2024-1102",
								Title:         "jberet: jberet-core logging database credentials",
								Summary:       "A vulnerability was found in jberet-core logging. An exception in 'dbProperties' might display user credentials such as the username and password for the database-connection.\nA vulnerability was found in jberet-core logging. An exception in 'dbProperties' might display user credentials such as the username and password for the database-connection.",
								Cvss3Score:    6.5,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
								Cvss3Severity: "Moderate",
								SourceLink:    "https://access.redhat.com/security/cve/CVE-2024-1102",
								CweIDs:        []string{"CWE-523"},
								References: models.References{
									{Link: "https://bugzilla.redhat.com/show_bug.cgi?id=2262060", Source: "REDHAT", RefID: "2262060"},
									{Link: "https://github.com/jberet/jsr352/issues/452", Source: "MISC"},
									{Link: "https://nvd.nist.gov/vuln/detail/CVE-2024-1102", Source: "NVD", RefID: "CVE-2024-1102"},
									{Link: "https://www.cve.org/CVERecord?id=CVE-2024-1102", Source: "CVE", RefID: "CVE-2024-1102"},
								},
								Published:    time.Date(2024, 1, 29, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC),
							},
						},
					},
					Mitigations: []models.Mitigation{
						{
							CveContentType: models.RedHatAPI,
							Mitigation:     "Mitigation for this issue is either not available or the currently available options don't meet the Red Hat Product Security criteria.",
							URL:            "https://access.redhat.com/security/cve/CVE-2024-1102",
						},
					},
				},
			},
		},
		{
			name: "CVE not found in DB leaves VulnInfo unchanged",
			args: args{
				vim: models.VulnInfos{
					"CVE-9999-0001": models.VulnInfo{
						CveID: "CVE-9999-0001",
						CveContents: models.CveContents{
							models.RedHat: []models.CveContent{
								{
									Type:  models.RedHat,
									CveID: "CVE-9999-0001",
									Title: "original",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-9999-0001": models.VulnInfo{
					CveID: "CVE-9999-0001",
					CveContents: models.CveContents{
						models.RedHat: []models.CveContent{
							{
								Type:  models.RedHat,
								CveID: "CVE-9999-0001",
								Title: "original",
							},
						},
					},
				},
			},
		},
		{
			name: "skip if RedHatAPI already present",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-1102": models.VulnInfo{
						CveID: "CVE-2024-1102",
						CveContents: models.CveContents{
							models.RedHatAPI: []models.CveContent{
								{
									Type:  models.RedHatAPI,
									CveID: "CVE-2024-1102",
									Title: "already-enriched",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-1102": models.VulnInfo{
					CveID: "CVE-2024-1102",
					CveContents: models.CveContents{
						models.RedHatAPI: []models.CveContent{
							{
								Type:  models.RedHatAPI,
								CveID: "CVE-2024-1102",
								Title: "already-enriched",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with nvd-feed-cve-v2 data (no pre-existing nvd content)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2014-0160": models.VulnInfo{
						CveID:       "CVE-2014-0160",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2014-0160": models.VulnInfo{
					CveID: "CVE-2014-0160",
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:          models.Nvd,
								CveID:         "CVE-2014-0160",
								Title:         "OpenSSL Heartbleed",
								Summary:       "The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory, aka the Heartbleed bug.",
								Cvss3Score:    7.5,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
								References: models.References{
									{Link: "http://www.us-cert.gov/ncas/alerts/TA14-098A", Source: "MISC"},
									{Link: "https://nvd.nist.gov/vuln/detail/CVE-2014-0160", Source: "NVD", RefID: "CVE-2014-0160"},
								},
								CweIDs:       []string{"CWE-125"},
								Published:    time.Date(2014, 4, 7, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(2014, 4, 8, 0, 0, 0, 0, time.UTC),
							},
						},
					},
					Exploits: []models.Exploit{
						{ExploitType: models.ExploitTypeNVD, URL: "https://www.exploit-db.com/exploits/32764"},
					},
					Mitigations: []models.Mitigation{
						{CveContentType: models.Nvd, URL: "Upgrade to OpenSSL 1.0.1g or later."},
					},
					AlertDict: models.AlertDict{
						USCERT: []models.Alert{
							{URL: "http://www.us-cert.gov/ncas/alerts/TA14-098A", Title: "US-CERT-TA14-098A", Team: "uscert"},
						},
					},
				},
			},
		},
		{
			name: "preserve existing nvd CveContent (hasContent) but still derive US-CERT",
			args: args{
				vim: models.VulnInfos{
					"CVE-2014-0160": models.VulnInfo{
						CveID: "CVE-2014-0160",
						CveContents: models.CveContents{
							models.Nvd: []models.CveContent{
								{
									Type:  models.Nvd,
									CveID: "CVE-2014-0160",
									Title: "from-cpe-detection",
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2014-0160": models.VulnInfo{
					CveID: "CVE-2014-0160",
					CveContents: models.CveContents{
						models.Nvd: []models.CveContent{
							{
								Type:  models.Nvd,
								CveID: "CVE-2014-0160",
								Title: "from-cpe-detection",
							},
						},
					},
					AlertDict: models.AlertDict{
						USCERT: []models.Alert{
							{URL: "http://www.us-cert.gov/ncas/alerts/TA14-098A", Title: "US-CERT-TA14-098A", Team: "uscert"},
						},
					},
				},
			},
		},
		{
			name: "enrich with cisa-kev data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2022-21971": models.VulnInfo{
						CveID:       "CVE-2022-21971",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2022-21971": models.VulnInfo{
					CveID:       "CVE-2022-21971",
					CveContents: models.CveContents{},
					KEVs: []models.KEV{
						{
							Type:                       models.CISAKEVType,
							VendorProject:              "Microsoft",
							Product:                    "Windows",
							VulnerabilityName:          "Microsoft Windows Runtime Remote Code Execution Vulnerability",
							ShortDescription:           "Microsoft Windows Runtime contains an unspecified vulnerability which allows for remote code execution.",
							RequiredAction:             "Apply updates per vendor instructions.",
							KnownRansomwareCampaignUse: "Unknown",
							DateAdded:                  time.Date(2022, time.August, 18, 0, 0, 0, 0, time.UTC),
							DueDate:                    new(time.Date(2022, time.September, 8, 0, 0, 0, 0, time.UTC)),
							CISA: &models.CISAKEV{
								Note: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21971",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with vulncheck-kev data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2021-30713": models.VulnInfo{
						CveID:       "CVE-2021-30713",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2021-30713": models.VulnInfo{
					CveID:       "CVE-2021-30713",
					CveContents: models.CveContents{},
					KEVs: []models.KEV{
						{
							Type:                       models.VulnCheckKEVType,
							VendorProject:              "Apple",
							Product:                    "MacOS X",
							VulnerabilityName:          "Apple macOS Unspecified Vulnerability",
							ShortDescription:           "Apple macOS Transparency, Consent, and Control (TCC) contains an unspecified permissions issue which may allow a malicious application to bypass privacy preferences.",
							RequiredAction:             "Apply updates per vendor instructions.",
							KnownRansomwareCampaignUse: "Unknown",
							DateAdded:                  time.Date(2021, time.November, 3, 0, 0, 0, 0, time.UTC),
							DueDate:                    new(time.Date(2021, time.November, 17, 0, 0, 0, 0, time.UTC)),
							VulnCheck: &models.VulnCheckKEV{
								XDB: []models.VulnCheckXDB{
									{
										XDBID:       "a1b2c3",
										XDBURL:      "https://vulncheck.com/xdb/a1b2c3",
										DateAdded:   time.Date(2022, time.March, 15, 0, 0, 0, 0, time.UTC),
										ExploitType: "initial_access",
										CloneSSHURL: "git@github.com:example/exploit.git",
									},
								},
								ReportedExploitation: []models.VulnCheckReportedExploitation{
									{
										URL:       "https://support.apple.com/kb/HT212529",
										DateAdded: time.Date(2022, time.January, 19, 0, 0, 0, 0, time.UTC),
									},
									{
										URL:       "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
										DateAdded: time.Date(2021, time.November, 3, 0, 0, 0, 0, time.UTC),
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with enisa-kev data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-9380": models.VulnInfo{
						CveID:       "CVE-2024-9380",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-9380": models.VulnInfo{
					CveID:       "CVE-2024-9380",
					CveContents: models.CveContents{},
					KEVs: []models.KEV{
						{
							Type:          models.ENISAKEVType,
							VendorProject: "Ivanti",
							Product:       "CSA (Cloud Services Appliance)",
							ENISA: &models.ENISAKEV{
								DateReported: time.Date(2025, time.January, 17, 0, 0, 0, 0, time.UTC),
								PatchedSince: "tbc",
								OriginSource: "cnw",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with enisa-euvd-list data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-56374": models.VulnInfo{
						CveID:       "CVE-2024-56374",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-56374": models.VulnInfo{
					CveID: "CVE-2024-56374",
					CveContents: models.CveContents{
						models.Euvd: []models.CveContent{
							{
								Type:          models.Euvd,
								CveID:         "CVE-2024-56374",
								Title:         "EUVD-2025-0001",
								Summary:       "An issue was discovered in Django 5.1 before 5.1.5, 5.0 before 5.0.11, and 4.2 before 4.2.18. Lack of upper-bound limit enforcement in strings passed when performing IPv6 validation could lead to a potential denial-of-service attack. The undocumented and private functions clean_ipv6_address and is_valid_ipv6_address are vulnerable, as is the django.forms.GenericIPAddressField form field. (The django.db.models.GenericIPAddressField model field is not affected.)",
								Cvss3Score:    5.8,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L",
								Cvss3Severity: "MEDIUM",
								SourceLink:    "https://euvd.enisa.europa.eu/vulnerability/EUVD-2025-0001",
								References: models.References{
									{Link: "https://docs.djangoproject.com/en/dev/releases/security/", Source: "MISC"},
									{Link: "https://groups.google.com/g/django-announce", Source: "MISC"},
									{Link: "https://www.djangoproject.com/weblog/2025/jan/14/security-releases/", Source: "MISC"},
								},
								Published:    time.Date(2025, 1, 14, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(2025, 2, 12, 20, 31, 20, 0, time.UTC),
							},
						},
					},
				},
			},
		},
		{
			// VulnCheck mirrors/enriches NVD: a CVE detected by another means
			// (here none pre-exists) gets a models.Vulncheck CveContent with the
			// console.vulncheck.com SourceLink. enrichVulnCheck early-returns when
			// a Vulncheck content already exists, so this exercises the fill path.
			name: "enrich with vulncheck-nist-nvd2 data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-3400": models.VulnInfo{
						CveID:       "CVE-2024-3400",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-3400": models.VulnInfo{
					CveID: "CVE-2024-3400",
					CveContents: models.CveContents{
						models.Vulncheck: []models.CveContent{
							{
								Type:          models.Vulncheck,
								CveID:         "CVE-2024-3400",
								Summary:       "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software enables an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
								Cvss3Score:    10.0,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
								Cvss3Severity: "CRITICAL",
								SourceLink:    "https://console.vulncheck.com/cve/CVE-2024-3400",
								References: models.References{
									{Link: "https://nvd.nist.gov/vuln/detail/CVE-2024-3400", Source: "NVD", RefID: "CVE-2024-3400"},
									{Link: "https://security.paloaltonetworks.com/CVE-2024-3400", Source: "MISC"},
								},
								CweIDs:       []string{"CWE-77"},
								Published:    time.Date(2024, 4, 12, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(2024, 4, 19, 0, 0, 0, 0, time.UTC),
							},
						},
					},
				},
			},
		},
		{
			// enrichJVN adds a minimal Jvn CveContent of only {Type, CveID,
			// SourceLink} pointing at the JVNDB advisory page, but SKIPS adding
			// when a Jvn CveContent with that same SourceLink already exists (the
			// richer postConvert detection entry is kept untouched). It also lifts
			// any JP-CERT alert from advisory references whose URL contains
			// "jpcert.or.jp/at/" into AlertDict.JPCERT.
			name: "enrich with jvn-feed-rss data (keeps the postConvert Jvn content, adds JP-CERT alert)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-21762": models.VulnInfo{
						CveID: "CVE-2024-21762",
						CveContents: models.CveContents{
							models.Jvn: []models.CveContent{
								{
									Type:       models.Jvn,
									CveID:      "CVE-2024-21762",
									SourceLink: "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000123.html",
									References: models.References{
										{Link: "https://example.jp/extra", Source: "MISC"},
									},
								},
							},
						},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-21762": models.VulnInfo{
					CveID: "CVE-2024-21762",
					CveContents: models.CveContents{
						models.Jvn: []models.CveContent{
							{
								Type:       models.Jvn,
								CveID:      "CVE-2024-21762",
								SourceLink: "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000123.html",
								References: models.References{
									{Link: "https://example.jp/extra", Source: "MISC"},
								},
							},
						},
					},
					AlertDict: models.AlertDict{
						JPCERT: []models.Alert{
							{
								Team:  "jpcert",
								URL:   "https://www.jpcert.or.jp/at/2024/at240008.html",
								Title: "Fortinet FortiOS におけるバッファエラーの脆弱性",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with jvn-feed-rss data (adds a source-link pointer when not JVN-detected)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-21762": models.VulnInfo{
						CveID:       "CVE-2024-21762",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-21762": models.VulnInfo{
					CveID: "CVE-2024-21762",
					CveContents: models.CveContents{
						models.Jvn: []models.CveContent{
							{
								Type:       models.Jvn,
								CveID:      "CVE-2024-21762",
								SourceLink: "https://jvndb.jvn.jp/ja/contents/2024/JVNDB-2024-000123.html",
							},
						},
					},
					AlertDict: models.AlertDict{
						JPCERT: []models.Alert{
							{
								Team:  "jpcert",
								URL:   "https://www.jpcert.or.jp/at/2024/at240008.html",
								Title: "Fortinet FortiOS におけるバッファエラーの脆弱性",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with metasploit data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2024-0012": models.VulnInfo{
						CveID:       "CVE-2024-0012",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2024-0012": models.VulnInfo{
					CveID:       "CVE-2024-0012",
					CveContents: models.CveContents{},
					Metasploits: []models.Metasploit{
						{
							Name:        "exploit/linux/http/panos_management_unauth_rce",
							Title:       "Palo Alto Networks PAN-OS Management Interface Unauthenticated Remote Code Execution",
							Description: "This module exploits an authentication bypass vulnerability (CVE-2024-0012).",
							URLs: []string{
								"https://security.paloaltonetworks.com/CVE-2024-0012",
								"https://www.cve.org/CVERecord?id=CVE-2024-0012",
							},
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-exploitdb data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-3132": models.VulnInfo{
						CveID:       "CVE-2017-3132",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-3132": models.VulnInfo{
					CveID:       "CVE-2017-3132",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeExploitDB,
							ID:          "42388",
							URL:         "https://www.exploit-db.com/exploits/42388",
							Description: "Fortinet FortiOS < 5.6.0 - Cross-Site Scripting",
							Verified:    new(true),
							DocumentURL: new("https://www.exploit-db.com/raw/42388"),
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-github data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-9779": models.VulnInfo{
						CveID:       "CVE-2017-9779",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-9779": models.VulnInfo{
					CveID:       "CVE-2017-9779",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeGitHub,
							URL:         "https://github.com/homjxi0e/CVE-2017-9779",
							Description: "Automatic execution Payload From Windows By Path Users All Exploit Via File bashrc ",
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-inthewild data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-16885": models.VulnInfo{
						CveID:       "CVE-2017-16885",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-16885": models.VulnInfo{
					CveID:       "CVE-2017-16885",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeInTheWild,
							URL:         "https://www.exploit-db.com/exploits/43460/",
						},
					},
				},
			},
		},
		{
			name: "enrich with exploit-trickest data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-7273": models.VulnInfo{
						CveID:       "CVE-2017-7273",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-7273": models.VulnInfo{
					CveID:       "CVE-2017-7273",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeTrickest,
							URL:         "https://github.com/thdusdl1219/CVE-Study",
							Description: "The cp_report_fixup function in drivers/hid/hid-cypress.c in the Linux kernel 3.2 and 4.x before 4.9.4 allows physically proximate attackers to cause a denial of service (integer underflow) or possibly have unspecified other impact via a crafted HID report.",
						},
						{
							ExploitType: models.ExploitTypeTrickest,
							URL:         "https://github.com/vincent-deng/veracode-container-security-finding-parser",
							Description: "The cp_report_fixup function in drivers/hid/hid-cypress.c in the Linux kernel 3.2 and 4.x before 4.9.4 allows physically proximate attackers to cause a denial of service (integer underflow) or possibly have unspecified other impact via a crafted HID report.",
						},
					},
				},
			},
		},
		{
			name: "enrich with nuclei-repository data (verified=true)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-18565": models.VulnInfo{
						CveID:       "CVE-2017-18565",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-18565": models.VulnInfo{
					CveID:       "CVE-2017-18565",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeNuclei,
							URL:         "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-18565.yaml",
							Description: "The updater plugin before 1.35 for WordPress has multiple XSS issues.",
							Verified:    new(true),
						},
					},
				},
			},
		},
		{
			name: "enrich with nuclei-repository data (verified=false)",
			args: args{
				vim: models.VulnInfos{
					"CVE-2017-14535": models.VulnInfo{
						CveID:       "CVE-2017-14535",
						CveContents: models.CveContents{},
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2017-14535": models.VulnInfo{
					CveID:       "CVE-2017-14535",
					CveContents: models.CveContents{},
					Exploits: []models.Exploit{
						{
							ExploitType: models.ExploitTypeNuclei,
							URL:         "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2017/CVE-2017-14535.yaml",
							Description: "Trixbox 2.8.0.4 is vulnerable to OS command injection via shell metacharacters in the lang parameter to /maint/modules/home/index.php.",
							Verified:    new(false),
						},
					},
				},
			},
		},
		{
			name: "empty VulnInfos",
			args: args{
				vim: models.VulnInfos{},
			},
			want: models.VulnInfos{},
		},
		{
			name: "enrich with mitre-cve-v5 data",
			args: args{
				vim: models.VulnInfos{
					"CVE-2023-44487": models.VulnInfo{
						CveID: "CVE-2023-44487",
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2023-44487": models.VulnInfo{
					CveID: "CVE-2023-44487",
					CveContents: models.CveContents{
						models.Mitre: []models.CveContent{
							{
								Type:         models.Mitre,
								CveID:        "CVE-2023-44487",
								Title:        "HTTP/2 Rapid Reset Attack",
								Summary:      "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
								SourceLink:   "https://www.cve.org/CVERecord?id=CVE-2023-44487",
								Published:    time.Date(2023, 10, 10, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC),
								SSVC: &models.SSVC{
									Exploitation:    "active",
									Automatable:     "yes",
									TechnicalImpact: "total",
								},
								Optional: map[string]string{"source": "ADP:CISA-ADP"},
							},
							{
								Type:          models.Mitre,
								CveID:         "CVE-2023-44487",
								Title:         "HTTP/2 Rapid Reset Attack",
								Summary:       "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.",
								Cvss3Score:    7.5,
								Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
								Cvss3Severity: "HIGH",
								SourceLink:    "https://www.cve.org/CVERecord?id=CVE-2023-44487",
								References: models.References{
									{Link: "https://www.cve.org/CVERecord?id=CVE-2023-44487", Source: "CVE", RefID: "CVE-2023-44487"},
								},
								Published:    time.Date(2023, 10, 10, 0, 0, 0, 0, time.UTC),
								LastModified: time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC),
								Optional:     map[string]string{"source": "CNA:cve@mitre.org"},
							},
						},
					},
				},
			},
		},
		{
			name: "datasource not in enrich filter is filtered out",
			args: args{
				vim: models.VulnInfos{
					"CVE-2020-0001": models.VulnInfo{
						CveID: "CVE-2020-0001",
					},
				},
			},
			want: models.VulnInfos{
				"CVE-2020-0001": models.VulnInfo{
					CveID:       "CVE-2020-0001",
					CveContents: models.CveContents{},
				},
			},
		},
	}

	c := session.Config{Type: "boltdb", Path: filepath.Join(t.TempDir(), "enrich-test.db")}
	if err := testutil.PopulateDB(c, "testdata/fixtures/enrich"); err != nil {
		t.Fatalf("PopulateDB() err: %v", err)
	}

	sesh, err := c.New()
	if err != nil {
		t.Fatalf("session.Config.New() err: %v", err)
	}
	if err := sesh.Storage().Open(); err != nil {
		t.Fatalf("Storage().Open() err: %v", err)
	}
	defer sesh.Storage().Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := vuls2.Enrich(sesh, tt.args.vim); (err != nil) != tt.wantErr {
				t.Errorf("enrich() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			diff, err := compareVulnInfos(tt.args.vim, tt.want)
			if err != nil {
				t.Errorf("enrich() compareVulnInfos() error = %v", err)
			}
			if diff != "" {
				t.Errorf("enrich() mismatch (-got +want):\n%s", diff)
			}
		})
	}
}

func compareVulnInfos(a, b models.VulnInfos) (string, error) {
	ks := make(map[string]struct{})
	for k := range a {
		ks[k] = struct{}{}
	}
	for k := range b {
		ks[k] = struct{}{}
	}

	var sb strings.Builder
	for k := range ks {
		if diff := gocmp.Diff(a[k], b[k], []gocmp.Option{
			gocmpopts.SortSlices(func(a, b models.Confidence) bool {
				return cmp.Compare(a.DetectionMethod, b.DetectionMethod) < 0
			}),
			gocmpopts.SortSlices(func(a, b models.DistroAdvisory) bool {
				return cmp.Or(
					cmp.Compare(a.AdvisoryID, b.AdvisoryID),
					cmp.Compare(a.Severity, b.Severity),
					a.Issued.Compare(b.Issued),
					a.Updated.Compare(b.Updated),
				) < 0
			}),
			gocmpopts.SortSlices(func(a, b models.PackageFixStatus) bool {
				return cmp.Or(
					cmp.Compare(a.Name, b.Name),
					cmp.Compare(a.FixState, b.FixState),
					cmp.Compare(a.FixedIn, b.FixedIn),
				) < 0
			}),
			gocmpopts.SortSlices(func(a, b models.Reference) bool {
				return cmp.Compare(a.Link, b.Link) < 0
			}),
			// enrich emits CveContent in map order (e.g. one per MITRE CNA/ADP
			// source); normalised downstream by CveContents.Sort, so compare
			// order-insensitively here using the same key order as that sort.
			gocmpopts.SortSlices(func(a, b models.CveContent) bool {
				return cmp.Or(
					cmp.Compare(b.Cvss40Score, a.Cvss40Score),
					cmp.Compare(b.Cvss3Score, a.Cvss3Score),
					cmp.Compare(b.Cvss2Score, a.Cvss2Score),
					cmp.Compare(a.SourceLink, b.SourceLink),
					cmp.Compare(a.Cvss40Vector, b.Cvss40Vector),
					cmp.Compare(a.Cvss3Vector, b.Cvss3Vector),
					cmp.Compare(a.Cvss2Vector, b.Cvss2Vector),
					cmp.Compare(fmt.Sprintf("%#v", a.Optional), fmt.Sprintf("%#v", b.Optional)),
				) < 0
			}),
		}...); diff != "" {
			sb.WriteString(fmt.Sprintf("%s: %s\n", k, diff))
		}
	}

	return sb.String(), nil
}

func Test_enrichCTI(t *testing.T) {
	tests := []struct {
		name           string
		vi             models.VulnInfo
		wantVi         models.VulnInfo
		wantCAPECDict  models.CAPECDict
		wantATTACKDict models.ATTACKDict
	}{
		{
			name: "cwe with capec+attack chain resolves all",
			vi: models.VulnInfo{
				CveID: "CVE-2024-TEST",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-TEST",
						CweIDs: []string{"CWE-306"},
					}},
				},
			},
			wantVi: models.VulnInfo{
				CveID: "CVE-2024-TEST",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-TEST",
						CweIDs: []string{"CWE-306"},
					}},
				},
				CTIs: []string{"CAPEC-115", "CAPEC-36", "T1552"},
			},
			wantCAPECDict: models.CAPECDict{
				"CAPEC-115": {CAPECID: "CAPEC-115", Name: "Authentication Bypass"},
				"CAPEC-36":  {CAPECID: "CAPEC-36", Name: "Using Unpublished Interfaces or Functionality"},
			},
			wantATTACKDict: models.ATTACKDict{
				"T1552": {ATTACKID: "T1552", Name: "Unsecured Credentials", Platforms: []string{"Linux", "Windows", "macOS"}},
			},
		},
		{
			name: "no CWE leaves VulnInfo untouched",
			vi: models.VulnInfo{
				CveID: "CVE-2024-NOCWE",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:  models.RedHatAPI,
						CveID: "CVE-2024-NOCWE",
					}},
				},
			},
			wantVi: models.VulnInfo{
				CveID: "CVE-2024-NOCWE",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:  models.RedHatAPI,
						CveID: "CVE-2024-NOCWE",
					}},
				},
			},
		},
		{
			name: "unknown CWE silently skipped",
			vi: models.VulnInfo{
				CveID: "CVE-2024-UNKNOWN",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-UNKNOWN",
						CweIDs: []string{"CWE-9999"},
					}},
				},
			},
			wantVi: models.VulnInfo{
				CveID: "CVE-2024-UNKNOWN",
				CveContents: models.CveContents{
					models.RedHatAPI: []models.CveContent{{
						Type:   models.RedHatAPI,
						CveID:  "CVE-2024-UNKNOWN",
						CweIDs: []string{"CWE-9999"},
					}},
				},
			},
		},
	}

	c := session.Config{Type: "boltdb", Path: filepath.Join(t.TempDir(), "enrich-cti.db")}
	if err := testutil.PopulateDB(c, "testdata/fixtures/enrich"); err != nil {
		t.Fatalf("PopulateDB() err: %v", err)
	}
	sesh, err := c.New()
	if err != nil {
		t.Fatalf("session.Config.New() err: %v", err)
	}
	if err := sesh.Storage().Open(); err != nil {
		t.Fatalf("Storage().Open() err: %v", err)
	}
	defer sesh.Storage().Close()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &models.ScanResult{ScannedCves: models.VulnInfos{tt.vi.CveID: tt.vi}}
			if err := vuls2.EnrichCTI(sesh, r); err != nil {
				t.Fatalf("EnrichCTI() err: %v", err)
			}
			if diff := gocmp.Diff(tt.wantVi, r.ScannedCves[tt.vi.CveID], gocmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("enrichCTI() VulnInfo mismatch (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantCAPECDict, r.CAPECDict); diff != "" {
				t.Errorf("enrichCTI() CAPECDict mismatch (-want +got):\n%s", diff)
			}
			if diff := gocmp.Diff(tt.wantATTACKDict, r.ATTACKDict); diff != "" {
				t.Errorf("enrichCTI() ATTACKDict mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_collectVerifiedProducts(t *testing.T) {
	tests := []struct {
		name     string
		detected detectTypes.DetectResult
		want     map[dataTypes.RootID]map[string]map[string]struct{}
	}{
		{
			// NVD (verified) and VulnCheck (suppressed) sit under the same CVE
			// root and define the same product: the product is derived for the
			// root's CVE.
			name: "same root: verified NVD product derived for suppressed VulnCheck",
			detected: detectTypes.DetectResult{
				Detected: []detectTypes.VulnerabilityData{
					{
						ID: "CVE-2024-0001",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendora:product1:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
									sourceTypes.VulnCheckNISTNVD2: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendora:product1:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.NVDAPICVE: {
										"CVE-2024-0001": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0001"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: map[dataTypes.RootID]map[string]map[string]struct{}{
				"CVE-2024-0001": {
					"CVE-2024-0001": {"a:vendora:product1": {}},
				},
			},
		},
		{
			// The verified source (NVD) and the suppressed source (JVN) alias
			// the same CVE under different roots — NVD under the CVE root, JVN
			// under a JVNDB-* root. The derived set is keyed to the suppressed
			// root via the shared CVE ID; the verified-only root is absent.
			name: "cross-root: NVD under CVE root feeds JVN under JVNDB root",
			detected: detectTypes.DetectResult{
				Detected: []detectTypes.VulnerabilityData{
					{
						ID: "CVE-2024-0002",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendorb:product2:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.NVDAPICVE: {
										"CVE-2024-0002": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0002"}},
										},
									},
								},
							},
						},
					},
					{
						ID: "JVNDB-2024-000002",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.JVNFeedDetail: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendorb:product2:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.JVNFeedDetail: {
										"JVNDB-2024-000002": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0002"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: map[dataTypes.RootID]map[string]map[string]struct{}{
				"JVNDB-2024-000002": {
					"CVE-2024-0002": {"a:vendorb:product2": {}},
				},
			},
		},
		{
			// A multi-CVE suppressed root must keep each CVE's verified product
			// separate: prodx (defined only for CVE-2024-000A) must not suppress
			// CVE-2024-000B and vice versa. JVN's JVNDB-* root is the realistic
			// multi-CVE carrier here — VulnCheck / NVD are rooted per CVE ID.
			name: "multi-CVE suppressed root keeps per-CVE product sets separate",
			detected: detectTypes.DetectResult{
				Detected: []detectTypes.VulnerabilityData{
					{
						ID: "CVE-2024-000A",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodx:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.NVDAPICVE: {
										"CVE-2024-000A": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-000A"}},
										},
									},
								},
							},
						},
					},
					{
						ID: "CVE-2024-000B",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prody:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.NVDAPICVE: {
										"CVE-2024-000B": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-000B"}},
										},
									},
								},
							},
						},
					},
					{
						ID: "JVNDB-2024-000099",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.JVNFeedRSS: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodx:*:*:*:*:*:*:*:*")}),
														},
													},
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prody:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.JVNFeedRSS: {
										"JVNDB-2024-000099": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-000A"}},
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-000B"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: map[dataTypes.RootID]map[string]map[string]struct{}{
				"JVNDB-2024-000099": {
					"CVE-2024-000A": {"a:vendor:prodx": {}},
					"CVE-2024-000B": {"a:vendor:prody": {}},
				},
			},
		},
		{
			// A suppressed root whose CVE has no verified-source product yields
			// no entry (nothing to suppress).
			name: "suppressed root with no verified product yields no entry",
			detected: detectTypes.DetectResult{
				Detected: []detectTypes.VulnerabilityData{
					{
						ID: "VC-only",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.VulnCheckNISTNVD2: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodz:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.VulnCheckNISTNVD2: {
										"VC-only": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0004"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: nil,
		},
		{
			// The primary CPE and its CPEMatches (version variants of the same
			// product) both fold to one part:vendor:product key, and a verified
			// detection in a non-CPE ecosystem is ignored.
			name: "CPEMatches fold to the product key; non-CPE ecosystem ignored",
			detected: detectTypes.DetectResult{
				Detected: []detectTypes.VulnerabilityData{
					{
						ID: "CVE-2024-0005",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE: new(ccTypes.Criterion{
																CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodp:*:*:*:*:*:*:*:*"),
																CPEMatches: []ccTypes.CPE{
																	ccTypes.CPE("cpe:2.3:a:vendor:prodp:1.0:*:*:*:*:*:*:*"),
																},
															}),
														},
													},
												},
											},
										},
									},
									sourceTypes.VulnCheckNISTNVD2: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodp:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
							{
								// Non-CPE ecosystem: even a verified source here is
								// ignored by collectVerifiedProducts.
								Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:ignored:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.NVDAPICVE: {
										"CVE-2024-0005": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0005"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: map[dataTypes.RootID]map[string]map[string]struct{}{
				"CVE-2024-0005": {
					"CVE-2024-0005": {"a:vendor:prodp": {}},
				},
			},
		},
		{
			// A suppressed source's own products must NOT be treated as verified:
			// only NVD's prodp is derived, not VulnCheck's prodw.
			name: "suppressed source's own products are not treated as verified",
			detected: detectTypes.DetectResult{
				Detected: []detectTypes.VulnerabilityData{
					{
						ID: "CVE-2024-0006",
						Detections: []detectTypes.VulnerabilityDataDetection{
							{
								Ecosystem: ecosystemTypes.EcosystemTypeCPE,
								Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
									sourceTypes.NVDAPICVE: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodp:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
									sourceTypes.VulnCheckNISTNVD2: {
										{
											Criteria: criteriaTypes.FilteredCriteria{
												Operator: criteriaTypes.CriteriaOperatorTypeOR,
												Criterions: []criterionTypes.FilteredCriterion{
													{
														Criterion: criterionTypes.Criterion{
															Type: criterionTypes.CriterionTypeCPE,
															CPE:  new(ccTypes.Criterion{CPE: ccTypes.CPE("cpe:2.3:a:vendor:prodw:*:*:*:*:*:*:*:*")}),
														},
													},
												},
											},
										},
									},
								},
							},
						},
						Vulnerabilities: []dbTypes.VulnerabilityDataVulnerability{
							{
								Contents: map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability{
									sourceTypes.NVDAPICVE: {
										"CVE-2024-0006": {
											{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0006"}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: map[dataTypes.RootID]map[string]map[string]struct{}{
				"CVE-2024-0006": {
					"CVE-2024-0006": {"a:vendor:prodp": {}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vuls2.CollectVerifiedProducts(tt.detected)
			if diff := gocmp.Diff(tt.want, got, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("collectVerifiedProducts() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
