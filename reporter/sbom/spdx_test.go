package sbom_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"

	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/reporter/sbom"
)

func TestToSPDX(t *testing.T) {
	tests := []struct {
		name string
		args models.ScanResult
		want spdx.Document
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
			want: spdx.Document{
				SPDXVersion:    spdx.Version,
				DataLicense:    spdx.DataLicense,
				SPDXIdentifier: "DOCUMENT",
				DocumentName:   "windows",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{Creator: "future-architect", CreatorType: "Organization"},
						{Creator: "test-tool", CreatorType: "Tool"},
					},
					Created: "2025-01-01T00:00:00Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "windows",
						PackageVersion:          "Windows Server 2022",
						PackageDownloadLocation: "NONE",
						PrimaryPackagePurpose:   "OPERATING-SYSTEM",
						Annotations: []spdx.Annotation{
							{
								Annotator:         spdx.Annotator{Annotator: "future-architect:vuls", AnnotatorType: "Tool"},
								AnnotationDate:    "2025-01-01T00:00:00Z",
								AnnotationType:    "Other",
								AnnotationComment: "OsFamily: windows",
							},
							{
								Annotator:         spdx.Annotator{Annotator: "future-architect:vuls", AnnotatorType: "Tool"},
								AnnotationDate:    "2025-01-01T00:00:00Z",
								AnnotationType:    "Other",
								AnnotationComment: "WindowsKB:Applied: 5022282",
							},
							{
								Annotator:         spdx.Annotator{Annotator: "future-architect:vuls", AnnotatorType: "Tool"},
								AnnotationDate:    "2025-01-01T00:00:00Z",
								AnnotationType:    "Other",
								AnnotationComment: "WindowsKB:Applied: 5025221",
							},
							{
								Annotator:         spdx.Annotator{Annotator: "future-architect:vuls", AnnotatorType: "Tool"},
								AnnotationDate:    "2025-01-01T00:00:00Z",
								AnnotationType:    "Other",
								AnnotationComment: "WindowsKB:Unapplied: 5026370",
							},
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{Relationship: "DESCRIBES"},
				},
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
			want: spdx.Document{
				SPDXVersion:    spdx.Version,
				DataLicense:    spdx.DataLicense,
				SPDXIdentifier: "DOCUMENT",
				DocumentName:   "centos",
				CreationInfo: &spdx.CreationInfo{
					Creators: []common.Creator{
						{Creator: "future-architect", CreatorType: "Organization"},
						{Creator: "test-tool", CreatorType: "Tool"},
					},
					Created: "2025-01-01T00:00:00Z",
				},
				Packages: []*spdx.Package{
					{
						PackageName:             "centos",
						PackageVersion:          "7",
						PackageDownloadLocation: "NONE",
						PrimaryPackagePurpose:   "OPERATING-SYSTEM",
						Annotations: []spdx.Annotation{
							{
								Annotator:         spdx.Annotator{Annotator: "future-architect:vuls", AnnotatorType: "Tool"},
								AnnotationDate:    "2025-01-01T00:00:00Z",
								AnnotationType:    "Other",
								AnnotationComment: "OsFamily: centos",
							},
						},
					},
				},
				Relationships: []*spdx.Relationship{
					{Relationship: "DESCRIBES"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sbom.ToSPDX(tt.args, "test-tool")

			opts := cmp.Options{
				cmpopts.IgnoreUnexported(spdx.Package{}),
				cmpopts.IgnoreFields(spdx.Document{}, "DocumentNamespace"),
				cmpopts.IgnoreFields(spdx.Package{}, "PackageSPDXIdentifier"),
				cmpopts.IgnoreFields(spdx.Relationship{}, "RefA", "RefB"),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("ToSPDX() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
