package reporter

import (
	"crypto/tls"
	"testing"

	"github.com/future-architect/vuls/config"
)

func TestNewSMTPClientTLSConfigUsesModernMinimumTLSVersion(t *testing.T) {
	conf := config.SMTPConf{
		SMTPAddr:              "smtp.example.com",
		TLSInsecureSkipVerify: true,
	}

	tlsConfig := newSMTPClientTLSConfig(conf)

	if tlsConfig.ServerName != conf.SMTPAddr {
		t.Fatalf("unexpected ServerName: got %q, want %q", tlsConfig.ServerName, conf.SMTPAddr)
	}
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("unexpected MinVersion: got %x, want %x", tlsConfig.MinVersion, tls.VersionTLS12)
	}
	if !tlsConfig.InsecureSkipVerify {
		t.Fatal("expected configured TLSInsecureSkipVerify value to be preserved")
	}
}
