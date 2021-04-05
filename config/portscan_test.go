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
		// The reason why wantErrNum is always set to 1 or more is because errors always occur in the path check of ScannerBinPath.
		{
			name:       "ApplyOptionNotUseExternalScanner",
			conf:       PortScanConf{IsUseExternalScanner: false, ScannerBinPath: "", HasPrivileged: false, ScanTechniques: []string{"sT"}, SourcePort: ""},
			wantErrNum: 2,
		},
		{
			name:       "NotSetScannerBinPath",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: false, ScanTechniques: []string{}, SourcePort: ""},
			wantErrNum: 1,
		},
		{
			name:       "UnsupportedScanTechnique",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: true, ScanTechniques: []string{"sU"}, SourcePort: ""},
			wantErrNum: 2,
		},
		{
			name:       "MultipleScanTechniques",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: true, ScanTechniques: []string{"sS", "sT"}, SourcePort: ""},
			wantErrNum: 2,
		},
		{
			name:       "NotHasPrivilegedScanTechniques",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: false, ScanTechniques: []string{"sS"}, SourcePort: ""},
			wantErrNum: 2,
		},
		{
			name:       "NotHasPrivilegedSourcePort",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: false, ScanTechniques: []string{"sT"}, SourcePort: "443"},
			wantErrNum: 2,
		},
		{
			name:       "InvalidSourcePortString",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: true, ScanTechniques: []string{"sS"}, SourcePort: "a"},
			wantErrNum: 2,
		},
		{
			name:       "InvalidSourcePortOutofRange",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: true, ScanTechniques: []string{"sS"}, SourcePort: "-1"},
			wantErrNum: 2,
		},
		{
			name:       "InvalidSourcePortZero",
			conf:       PortScanConf{IsUseExternalScanner: true, ScannerBinPath: "", HasPrivileged: true, ScanTechniques: []string{"sS"}, SourcePort: "0"},
			wantErrNum: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.conf.Validate(); len(err) != tt.wantErrNum {
				t.Errorf("PortScanConf.Validate() error = %v, len(error) = %d, wantErrNum %d", err, len(err), tt.wantErrNum)
			}
		})
	}
}
