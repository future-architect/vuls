//go:build !scanner
// +build !scanner

package detector

import (
	"reflect"
	"testing"

	"github.com/future-architect/vuls/models"
	cvemodels "github.com/vulsio/go-cve-dictionary/models"
)

func Test_getMaxConfidence(t *testing.T) {
	type args struct {
		detail cvemodels.CveDetail
	}
	tests := []struct {
		name    string
		args    args
		wantMax models.Confidence
	}{
		{
			name: "JvnVendorProductMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{},
					Jvns: []cvemodels.Jvn{{}},
				},
			},
			wantMax: models.JvnVendorProductMatch,
		},
		{
			name: "NvdExactVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdRoughVersionMatch},
						{DetectionMethod: cvemodels.NvdVendorProductMatch},
						{DetectionMethod: cvemodels.NvdExactVersionMatch},
					},
					Jvns: []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
				},
			},
			wantMax: models.NvdExactVersionMatch,
		},
		{
			name: "NvdRoughVersionMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdRoughVersionMatch},
						{DetectionMethod: cvemodels.NvdVendorProductMatch},
					},
					Jvns: []cvemodels.Jvn{},
				},
			},
			wantMax: models.NvdRoughVersionMatch,
		},
		{
			name: "NvdVendorProductMatch",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{
						{DetectionMethod: cvemodels.NvdVendorProductMatch},
					},
					Jvns: []cvemodels.Jvn{{DetectionMethod: cvemodels.JvnVendorProductMatch}},
				},
			},
			wantMax: models.NvdVendorProductMatch,
		},
		{
			name: "empty",
			args: args{
				detail: cvemodels.CveDetail{
					Nvds: []cvemodels.Nvd{},
					Jvns: []cvemodels.Jvn{},
				},
			},
			wantMax: models.Confidence{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotMax := getMaxConfidence(tt.args.detail); !reflect.DeepEqual(gotMax, tt.wantMax) {
				t.Errorf("getMaxConfidence() = %v, want %v", gotMax, tt.wantMax)
			}
		})
	}
}
