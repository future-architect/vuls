package vuls2_test

import (
	"reflect"
	"testing"

	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/future-architect/vuls/detector/vuls2"
	"github.com/future-architect/vuls/models"
)

func Test_postConvert(t *testing.T) {
	type args struct {
		scanned  scanTypes.ScanResult
		detected detectTypes.DetectResult
	}
	tests := []struct {
		name    string
		args    args
		want    models.VulnInfos
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := vuls2.PostConvert(tt.args.scanned, tt.args.detected)
			if (err != nil) != tt.wantErr {
				t.Errorf("postConvert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("postConvert() = %v, want %v", got, tt.want)
			}
		})
	}
}
