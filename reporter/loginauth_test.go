package reporter

import (
	"net/smtp"
	"testing"
)

func TestLoginAuthStart(t *testing.T) {
	t.Parallel()
	auth := &loginAuth{username: "user@example.com", password: "secret"}
	mech, resp, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: true})
	if err != nil {
		t.Fatalf("Start() returned error: %v", err)
	}
	if mech != "LOGIN" {
		t.Errorf("Start() mechanism = %q, want %q", mech, "LOGIN")
	}
	if resp != nil {
		t.Errorf("Start() resp = %v, want nil", resp)
	}
}

func TestLoginAuthNext(t *testing.T) {
	t.Parallel()
	auth := &loginAuth{username: "user@example.com", password: "s3cret"}

	tests := []struct {
		name       string
		fromServer string
		more       bool
		want       string
		wantNil    bool
	}{
		{name: "username prompt", fromServer: "Username:", more: true, want: "user@example.com"},
		{name: "password prompt", fromServer: "Password:", more: true, want: "s3cret"},
		{name: "username lowercase", fromServer: "username:", more: true, want: "user@example.com"},
		{name: "password lowercase", fromServer: "password:", more: true, want: "s3cret"},
		{name: "not more", fromServer: "", more: false, wantNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.Next([]byte(tt.fromServer), tt.more)
			if err != nil {
				t.Fatalf("Next() returned error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("Next() = %q, want nil", got)
				}
				return
			}
			if string(got) != tt.want {
				t.Errorf("Next() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLoginAuthNextUnexpectedChallenge(t *testing.T) {
	t.Parallel()
	auth := &loginAuth{username: "user", password: "pass"}
	_, err := auth.Next([]byte("Something unexpected:"), true)
	if err == nil {
		t.Fatal("Next() should return error for unexpected challenge")
	}
}
