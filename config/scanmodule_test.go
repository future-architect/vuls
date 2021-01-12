package config

import (
	"testing"
)

func TestScanModule_IsZero(t *testing.T) {
	tests := []struct {
		name  string
		modes []byte
		want  bool
	}{
		{
			name:  "not zero",
			modes: []byte{OSPkg},
			want:  false,
		},
		{
			name:  "zero",
			modes: []byte{},
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScanModule{}
			for _, b := range tt.modes {
				s.Set(b)
			}
			if got := s.IsZero(); got != tt.want {
				t.Errorf("ScanModule.IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScanModule_validate(t *testing.T) {
	tests := []struct {
		name    string
		modes   []byte
		wantErr bool
	}{
		{
			name:    "valid",
			modes:   []byte{},
			wantErr: false,
		},
		{
			name:    "err",
			modes:   []byte{WordPress, Lockfile, Port},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ScanModule{}
			for _, b := range tt.modes {
				s.Set(b)
			}
			if err := s.ensure(); (err != nil) != tt.wantErr {
				t.Errorf("ScanModule.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
