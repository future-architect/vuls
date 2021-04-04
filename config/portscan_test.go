package config

import (
	"reflect"
	"testing"
)

func TestPortScanConf_getScanTechniques(t *testing.T) {
	tests := []struct {
		name       string
		techniques []string
		want       []ScanTechnique
	}{
		{
			name:       "nil",
			techniques: []string{},
			want:       []ScanTechnique{},
		},
		{
			name:       "single",
			techniques: []string{"sS"},
			want:       []ScanTechnique{TCPSYN},
		},
		{
			name:       "multiple",
			techniques: []string{"sS", "sT"},
			want:       []ScanTechnique{TCPSYN, TCPConnect},
		},
		{
			name:       "unknown",
			techniques: []string{"sU"},
			want:       []ScanTechnique{NotSupportTechnique},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := PortScanConf{ScanTechniques: tt.techniques}
			if got := c.GetScanTechniques(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PortScanConf.getScanTechniques() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortScanConf_IsZero(t *testing.T) {
	tests := []struct {
		name string
		conf PortScanConf
		want bool
	}{
		{
			name: "not zero",
			conf: PortScanConf{ScannerBinPath: "/usr/bin/nmap"},
			want: false,
		},
		{
			name: "zero",
			conf: PortScanConf{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.conf.IsZero(); got != tt.want {
				t.Errorf("PortScanConf.IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPortScanConf_Validate(t *testing.T) {
	tests := []struct {
		name       string
		conf       PortScanConf
		wantErrNum int
	}{
		{
			name:       "NotSetScannerBinPath",
			conf:       PortScanConf{ExternalScannerMode: false, ScanTechniques: []string{"sS"}},
			wantErrNum: 1,
		},
		{
			name:       "UnsupportedScanTechnique",
			conf:       PortScanConf{ExternalScannerMode: true, ScannerBinPath: "", ScanTechniques: []string{"sU"}},
			wantErrNum: 1,
		},
		{
			name:       "MultipleScanTechniques",
			conf:       PortScanConf{ExternalScannerMode: true, ScannerBinPath: "", ScanTechniques: []string{"sS", "sT"}},
			wantErrNum: 1,
		},
		{
			name:       "InvalidSourceAddress",
			conf:       PortScanConf{ExternalScannerMode: true, ScannerBinPath: "", SourceAddress: "192.168.1.a"},
			wantErrNum: 1,
		},
		{
			name:       "InvalidSourcePort",
			conf:       PortScanConf{ExternalScannerMode: true, ScannerBinPath: "", SourcePort: "a"},
			wantErrNum: 1,
		},
		{
			name:       "InvalidSourcePort2",
			conf:       PortScanConf{ExternalScannerMode: true, ScannerBinPath: "", SourcePort: "-1"},
			wantErrNum: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.conf.Validate(); len(err) != tt.wantErrNum+1 {
				t.Errorf("PortScanConf.Validate() error = %v, len(error) = %d, wantErrNum %d", err, len(err), tt.wantErrNum+1)
			}
		})
	}
}
