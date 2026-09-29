package vuls2

import (
	"reflect"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	v31 "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

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

func Test_advisoryReference(t *testing.T) {
	type args struct {
		e  ecosystemTypes.Ecosystem
		s  sourceTypes.SourceID
		da models.DistroAdvisory
	}
	tests := []struct {
		name    string
		args    args
		want    models.Reference
		wantErr bool
	}{
		{
			name: "ubuntu notice",
			args: args{e: ecosystemTypes.Ecosystem("ubuntu:22.04"), s: sourceTypes.UbuntuOVAL, da: models.DistroAdvisory{AdvisoryID: "USN-6000-1"}},
			want: models.Reference{Link: "https://ubuntu.com/security/notices/USN-6000-1", Source: "UBUNTU", RefID: "USN-6000-1"},
		},
		{
			name: "solaris advisory id is the oracle security alert slug",
			args: args{e: ecosystemTypes.Ecosystem("solaris:11.4"), s: sourceTypes.SourceID("oracle-solaris"), da: models.DistroAdvisory{AdvisoryID: "bulletinjul2026"}},
			want: models.Reference{Link: "https://www.oracle.com/security-alerts/bulletinjul2026.html", Source: "ORACLE", RefID: "bulletinjul2026"},
		},
		{
			name:    "unknown family",
			args:    args{e: ecosystemTypes.Ecosystem("unknown:1"), s: sourceTypes.SourceID("unknown"), da: models.DistroAdvisory{AdvisoryID: "X-1"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := advisoryReference(tt.args.e, tt.args.s, tt.args.da)
			if (err != nil) != tt.wantErr {
				t.Fatalf("advisoryReference() error = %v, wantErr %v", err, tt.wantErr)
			}
			if diff := gocmp.Diff(tt.want, got); diff != "" {
				t.Errorf("advisoryReference() (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_toCveContentType(t *testing.T) {
	type args struct {
		e ecosystemTypes.Ecosystem
		s sourceTypes.SourceID
	}
	tests := []struct {
		name string
		args args
		want models.CveContentType
	}{
		{name: "cpe from nvd", args: args{e: ecosystemTypes.Ecosystem("cpe"), s: sourceTypes.NVDAPICVE}, want: models.Nvd},
		{name: "microsoft", args: args{e: ecosystemTypes.Ecosystem("microsoft:10"), s: sourceTypes.MicrosoftCSAF}, want: models.Microsoft},
		{name: "solaris", args: args{e: ecosystemTypes.Ecosystem("solaris:10"), s: sourceTypes.SourceID("oracle-solaris")}, want: models.Solaris},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toCveContentType(tt.args.e, tt.args.s); got != tt.want {
				t.Errorf("toCveContentType() = %s, want %s", got, tt.want)
			}
		})
	}
}

func Test_cveContentSourceLink(t *testing.T) {
	type args struct {
		ccType models.CveContentType
		v      vulnerabilityTypes.Vulnerability
		rootID dataTypes.RootID
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "alpine links the cve",
			args: args{ccType: models.Alpine, v: vulnerabilityTypes.Vulnerability{Content: contentTypes.Content{ID: "CVE-2024-0001"}}, rootID: dataTypes.RootID("CVE-2024-0001")},
			want: "https://security.alpinelinux.org/vuln/CVE-2024-0001",
		},
		{
			name: "fortinet links the advisory root",
			args: args{ccType: models.Fortinet, v: vulnerabilityTypes.Vulnerability{Content: contentTypes.Content{ID: "CVE-2024-0001"}}, rootID: dataTypes.RootID("FG-IR-24-041")},
			want: "https://www.fortiguard.com/psirt/FG-IR-24-041",
		},
		{
			name: "solaris links the advisory root",
			args: args{ccType: models.Solaris, v: vulnerabilityTypes.Vulnerability{Content: contentTypes.Content{ID: "CVE-2024-0001"}}, rootID: dataTypes.RootID("bulletinjul2026")},
			want: "https://www.oracle.com/security-alerts/bulletinjul2026.html",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cveContentSourceLink(tt.args.ccType, tt.args.v, tt.args.rootID); got != tt.want {
				t.Errorf("cveContentSourceLink() = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test_toVuls0Confidence(t *testing.T) {
	type args struct {
		e  ecosystemTypes.Ecosystem
		s  sourceTypes.SourceID
		sd sourceData
	}
	tests := []struct {
		name string
		args args
		want models.Confidence
	}{
		{name: "cpe exact match from nvd", args: args{e: ecosystemTypes.Ecosystem("cpe"), s: sourceTypes.NVDAPICVE, sd: sourceData{exactCpes: []string{"cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}}}, want: models.NvdExactVersionMatch},
		{name: "cpe vendor:product match from nvd", args: args{e: ecosystemTypes.Ecosystem("cpe"), s: sourceTypes.NVDAPICVE, sd: sourceData{vpCpes: []string{"cpe:2.3:a:x:y:*:*:*:*:*:*:*:*"}}}, want: models.NvdVendorProductMatch},
		{name: "alpine", args: args{e: ecosystemTypes.Ecosystem("alpine:3.20"), s: sourceTypes.AlpineSecDB}, want: models.OvalMatch},
		{name: "solaris", args: args{e: ecosystemTypes.Ecosystem("solaris:11.4"), s: sourceTypes.SourceID("oracle-solaris")}, want: models.OracleSolarisAdvisoryMatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toVuls0Confidence(tt.args.e, tt.args.s, tt.args.sd); got != tt.want {
				t.Errorf("toVuls0Confidence() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
