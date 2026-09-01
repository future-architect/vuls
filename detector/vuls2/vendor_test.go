package vuls2

import (
	"reflect"
	"testing"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"

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

func Test_splitCveContentBySource(t *testing.T) {
	base := models.CveContent{
		Type:       models.Nvd,
		CveID:      "CVE-0000-0000",
		Summary:    "summary",
		SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
		// Filled from every source by the caller; the split overwrites both
		// per source.
		Cvss3Score:  7.5,
		Cvss3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		CweIDs:      []string{"CWE-125", "CWE-126"},
		Optional:    map[string]string{"vuls2-sources": "[]"},
	}

	type args struct {
		base models.CveContent
		ss   []severityTypes.Severity
		cwes []cweTypes.CWE
	}
	tests := []struct {
		name string
		args args
		want []models.CveContent
	}{
		{
			name: "one content per source, ordered by source",
			args: args{
				base: base,
				ss: []severityTypes.Severity{
					{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  "nvd@nist.gov",
						CVSSv31: &v31.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", BaseScore: 7.5, BaseSeverity: "HIGH"},
					},
					{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  "openssl-security@openssl.org",
						CVSSv31: &v31.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", BaseScore: 5.3, BaseSeverity: "MEDIUM"},
					},
				},
				cwes: []cweTypes.CWE{
					{Source: "nvd@nist.gov", CWE: []string{"CWE-125"}},
					{Source: "openssl-security@openssl.org", CWE: []string{"CWE-126"}},
				},
			},
			want: []models.CveContent{
				{
					Type:          models.Nvd,
					CveID:         "CVE-0000-0000",
					Summary:       "summary",
					SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
					Cvss3Score:    7.5,
					Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Cvss3Severity: "HIGH",
					CweIDs:        []string{"CWE-125"},
					Optional:      map[string]string{"vuls2-sources": "[]", "source": "nvd@nist.gov"},
				},
				{
					Type:          models.Nvd,
					CveID:         "CVE-0000-0000",
					Summary:       "summary",
					SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
					Cvss3Score:    5.3,
					Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
					Cvss3Severity: "MEDIUM",
					CweIDs:        []string{"CWE-126"},
					Optional:      map[string]string{"vuls2-sources": "[]", "source": "openssl-security@openssl.org"},
				},
			},
		},
		{
			name: "a source with only a CWE keeps its entry without CVSS",
			args: args{
				base: base,
				ss: []severityTypes.Severity{
					{
						Type:    severityTypes.SeverityTypeCVSSv31,
						Source:  "nvd@nist.gov",
						CVSSv31: &v31.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", BaseScore: 7.5, BaseSeverity: "HIGH"},
					},
				},
				cwes: []cweTypes.CWE{
					{Source: "psirt@example.com", CWE: []string{"CWE-126"}},
				},
			},
			want: []models.CveContent{
				{
					Type:          models.Nvd,
					CveID:         "CVE-0000-0000",
					Summary:       "summary",
					SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
					Cvss3Score:    7.5,
					Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Cvss3Severity: "HIGH",
					Optional:      map[string]string{"vuls2-sources": "[]", "source": "nvd@nist.gov"},
				},
				{
					Type:       models.Nvd,
					CveID:      "CVE-0000-0000",
					Summary:    "summary",
					SourceLink: "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
					CweIDs:     []string{"CWE-126"},
					Optional:   map[string]string{"vuls2-sources": "[]", "source": "psirt@example.com"},
				},
			},
		},
		{
			name: "unattributed severity yields a single unlabelled content",
			args: args{
				base: base,
				ss: []severityTypes.Severity{
					{
						Type:    severityTypes.SeverityTypeCVSSv31,
						CVSSv31: &v31.CVSSv31{Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", BaseScore: 7.5, BaseSeverity: "HIGH"},
					},
				},
				cwes: []cweTypes.CWE{{CWE: []string{"CWE-125", "CWE-126"}}},
			},
			want: []models.CveContent{
				{
					Type:          models.Nvd,
					CveID:         "CVE-0000-0000",
					Summary:       "summary",
					SourceLink:    "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
					Cvss3Score:    7.5,
					Cvss3Vector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
					Cvss3Severity: "HIGH",
					CweIDs:        []string{"CWE-125", "CWE-126"},
					Optional:      map[string]string{"vuls2-sources": "[]"},
				},
			},
		},
		{
			name: "nothing to attribute returns base as-is",
			args: args{base: base},
			want: []models.CveContent{base},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCveContentBySource(tt.args.base, tt.args.ss, tt.args.cwes, enrichCvss)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCveContentBySource() = %#v, want %#v", got, tt.want)
			}
			// Optional is shared with the caller's content, so the per-source
			// label must never be written into it.
			if _, ok := tt.args.base.Optional["source"]; ok {
				t.Errorf("splitCveContentBySource() mutated base.Optional: %#v", tt.args.base.Optional)
			}
		})
	}
}

func Test_tagPocket(t *testing.T) {
	tests := []struct {
		name string
		tag  segmentTypes.DetectionTag
		want pocket
	}{
		{name: "plain release", tag: "noble_medium", want: pocketArchive},
		{name: "plain release without priority", tag: "noble", want: pocketArchive},
		{name: "esm-apps", tag: "esm-apps/noble_medium", want: pocketESM},
		{name: "esm-infra", tag: "esm-infra/xenial_low", want: pocketESM},
		{name: "esm-infra-legacy", tag: "esm-infra-legacy/trusty_medium", want: pocketESM},
		{name: "esm-apps-legacy", tag: "esm-apps-legacy/xenial_medium", want: pocketESM},
		// The tracker also writes the service on the right of the slash.
		{name: "release/esm", tag: "trusty/esm_medium", want: pocketESM},
		{name: "fips", tag: "fips/xenial_low", want: pocketFIPS},
		{name: "fips-updates", tag: "fips-updates/jammy_low", want: pocketFIPS},
		{name: "unknown service", tag: "realtime/jammy_low", want: pocketUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tagPocket(tt.tag); got != tt.want {
				t.Errorf("tagPocket() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_installedPocket(t *testing.T) {
	tests := []struct {
		name string
		pkg  scanTypes.OSPackage
		want pocket
	}{
		{name: "archive", pkg: scanTypes.OSPackage{Version: "3.4.0-1", SrcVersion: "3.4.0-1"}, want: pocketArchive},
		{name: "esm reserving the next archive version", pkg: scanTypes.OSPackage{Version: "3.4.0-1ubuntu0.1~esm1", SrcVersion: "3.4.0-1ubuntu0.1~esm1"}, want: pocketESM},
		{name: "esm above the current archive version", pkg: scanTypes.OSPackage{Version: "6.1.1-3ubuntu5+esm10", SrcVersion: "6.1.1-3ubuntu5+esm10"}, want: pocketESM},
		{name: "esm with a dotted counter", pkg: scanTypes.OSPackage{Version: "5.15.0-70.77+esm.1", SrcVersion: "5.15.0-70.77+esm.1"}, want: pocketESM},
		{name: "fips", pkg: scanTypes.OSPackage{Version: "1.0.2g-1ubuntu4.fips.4.20.9", SrcVersion: "1.0.2g-1ubuntu4.fips.4.20.9"}, want: pocketFIPS},
		{name: "fips with a plus", pkg: scanTypes.OSPackage{Version: "5.15.0-70.77+fips.1", SrcVersion: "5.15.0-70.77+fips.1"}, want: pocketFIPS},
		// esm-infra republishes plain archive versions for CVEs fixed before a
		// release left standard support; those Pro builds are indistinguishable
		// from archive ones and fall back through pocketFallbacks instead.
		{name: "esm build carrying no marker reads as archive", pkg: scanTypes.OSPackage{Version: "4.15.0-1146.161~14.04.1", SrcVersion: "4.15.0-1146.161~14.04.1"}, want: pocketArchive},
		{name: "binary version alone is enough", pkg: scanTypes.OSPackage{Version: "3.4.0-1ubuntu0.1~esm1"}, want: pocketESM},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := installedPocket(tt.pkg); got != tt.want {
				t.Errorf("installedPocket() = %v, want %v", got, tt.want)
			}
		})
	}
}
