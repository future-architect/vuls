package reporter

import (
	"testing"

	"github.com/future-architect/vuls/config"
)

func TestNewSMTPClientTLSConfig(t *testing.T) {
	tests := []struct {
		name               string
		conf               config.SMTPConf
		wantServerName     string
		wantInsecureVerify bool
	}{
		{
			name: "uses SMTP host and verifies certificates by default",
			conf: config.SMTPConf{
				SMTPAddr: "smtp.example.com",
			},
			wantServerName:     "smtp.example.com",
			wantInsecureVerify: false,
		},
		{
			name: "preserves configured insecure certificate verification",
			conf: config.SMTPConf{
				SMTPAddr:              "mail.internal.example",
				TLSInsecureSkipVerify: true,
			},
			wantServerName:     "mail.internal.example",
			wantInsecureVerify: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tlsConfig := newSMTPClientTLSConfig(tt.conf)

			if tlsConfig.ServerName != tt.wantServerName {
				t.Fatalf("unexpected ServerName: got %q, want %q", tlsConfig.ServerName, tt.wantServerName)
			}
			if tlsConfig.MinVersion != 0 {
				t.Fatalf("unexpected MinVersion: got %x, want 0 so Go can apply the stdlib default", tlsConfig.MinVersion)
			}
			if tlsConfig.InsecureSkipVerify != tt.wantInsecureVerify {
				t.Fatalf("unexpected InsecureSkipVerify: got %t, want %t", tlsConfig.InsecureSkipVerify, tt.wantInsecureVerify)
			}
			if tlsConfig.MaxVersion != 0 {
				t.Fatalf("unexpected MaxVersion: got %x, want 0 so Go can negotiate newer TLS versions", tlsConfig.MaxVersion)
			}
		})
	}
}
