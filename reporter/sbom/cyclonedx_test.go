package sbom_test

import (
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter/sbom"
)

func TestToCycloneDX(t *testing.T) {
	tests := []struct {
		name string
		args models.ScanResult
		want *cdx.BOM
	}{
		{
			name: "windows",
			args: models.ScanResult{
				Family:           "windows",
				Release:          "Windows Server 2022",
				ReportedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ReportedVersion:  "v0.38.5",
				ReportedRevision: "build-20260311_001506_6827f2d",
				WindowsKB: &models.WindowsKB{
					Applied:   []string{"5025221", "5022282"},
					Unapplied: []string{"5026370"},
				},
			},
			want: &cdx.BOM{
				XMLNS:       "http://cyclonedx.org/schema/bom/1.6",
				JSONSchema:  "http://cyclonedx.org/schema/bom-1.6.schema.json",
				BOMFormat:   "CycloneDX",
				SpecVersion: cdx.SpecVersion1_6,
				Version:     1,
				Metadata: &cdx.Metadata{
					Timestamp: "2025-01-01T00:00:00Z",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Group:   "future-architect",
								Name:    "vuls",
								Version: "v0.38.5-build-20260311_001506_6827f2d",
							},
						},
					},
					Component: &cdx.Component{
						Type:    cdx.ComponentTypeOS,
						Name:    "windows",
						Version: "Windows Server 2022",
						Properties: &[]cdx.Property{
							{Name: "future-architect:vuls:Type", Value: "windows"},
							{Name: "future-architect:vuls:WindowsKB:Applied", Value: "5025221"},
							{Name: "future-architect:vuls:WindowsKB:Applied", Value: "5022282"},
							{Name: "future-architect:vuls:WindowsKB:Unapplied", Value: "5026370"},
						},
					},
				},
				Components:      new([]cdx.Component),
				Dependencies:    &[]cdx.Dependency{},
				Vulnerabilities: &[]cdx.Vulnerability{},
			},
		},
		{
			name: "non-windows",
			args: models.ScanResult{
				Family:           "centos",
				Release:          "7",
				ReportedAt:       time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				ReportedVersion:  "v0.38.5",
				ReportedRevision: "build-20260311_001506_6827f2d",
			},
			want: &cdx.BOM{
				XMLNS:       "http://cyclonedx.org/schema/bom/1.6",
				JSONSchema:  "http://cyclonedx.org/schema/bom-1.6.schema.json",
				BOMFormat:   "CycloneDX",
				SpecVersion: cdx.SpecVersion1_6,
				Version:     1,
				Metadata: &cdx.Metadata{
					Timestamp: "2025-01-01T00:00:00Z",
					Tools: &cdx.ToolsChoice{
						Components: &[]cdx.Component{
							{
								Type:    cdx.ComponentTypeApplication,
								Group:   "future-architect",
								Name:    "vuls",
								Version: "v0.38.5-build-20260311_001506_6827f2d",
							},
						},
					},
					Component: &cdx.Component{
						Type:    cdx.ComponentTypeOS,
						Name:    "centos",
						Version: "7",
						Properties: &[]cdx.Property{
							{Name: "future-architect:vuls:Type", Value: "centos"},
						},
					},
				},
				Components:      new([]cdx.Component),
				Dependencies:    &[]cdx.Dependency{},
				Vulnerabilities: &[]cdx.Vulnerability{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sbom.ToCycloneDX(tt.args)

			opts := cmp.Options{
				cmpopts.IgnoreFields(cdx.BOM{}, "SerialNumber"),
				cmpopts.IgnoreFields(cdx.Component{}, "BOMRef"),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("ToCycloneDX() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
