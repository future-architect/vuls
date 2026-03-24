package reporter

import (
	"net/smtp"
	"testing"
)

func TestLoginAuthStart(t *testing.T) {
	t.Parallel()

	t.Run("TLS connection succeeds", func(t *testing.T) {
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
	})

	t.Run("non-TLS with LOGIN advertised succeeds", func(t *testing.T) {
		t.Parallel()
		auth := &loginAuth{username: "user@example.com", password: "secret"}
		mech, _, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: false, Auth: []string{"LOGIN"}})
		if err != nil {
			t.Fatalf("Start() returned error: %v", err)
		}
		if mech != "LOGIN" {
			t.Errorf("Start() mechanism = %q, want %q", mech, "LOGIN")
		}
	})

	t.Run("non-TLS without LOGIN advertised fails", func(t *testing.T) {
		t.Parallel()
		auth := &loginAuth{username: "user@example.com", password: "secret"}
		_, _, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: false})
		if err == nil {
			t.Fatal("Start() should return error for non-TLS connection without LOGIN advertised")
		}
	})
}

func TestLoginAuthNext(t *testing.T) {
	t.Parallel()

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
			t.Parallel()
			auth := &loginAuth{username: "user@example.com", password: "s3cret"}
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

func TestPlainAuthStart(t *testing.T) {
	t.Parallel()

	t.Run("TLS connection succeeds", func(t *testing.T) {
		t.Parallel()
		auth := &plainAuth{identity: "", username: "user@example.com", password: "secret"}
		mech, resp, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: true})
		if err != nil {
			t.Fatalf("Start() returned error: %v", err)
		}
		if mech != "PLAIN" {
			t.Errorf("Start() mechanism = %q, want %q", mech, "PLAIN")
		}
		want := "\x00user@example.com\x00secret"
		if string(resp) != want {
			t.Errorf("Start() resp = %q, want %q", resp, want)
		}
	})

	t.Run("non-TLS with PLAIN advertised succeeds", func(t *testing.T) {
		t.Parallel()
		auth := &plainAuth{identity: "", username: "user@example.com", password: "secret"}
		mech, _, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: false, Auth: []string{"PLAIN"}})
		if err != nil {
			t.Fatalf("Start() returned error: %v", err)
		}
		if mech != "PLAIN" {
			t.Errorf("Start() mechanism = %q, want %q", mech, "PLAIN")
		}
	})

	t.Run("non-TLS without PLAIN advertised fails", func(t *testing.T) {
		t.Parallel()
		auth := &plainAuth{identity: "", username: "user@example.com", password: "secret"}
		_, _, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: false})
		if err == nil {
			t.Fatal("Start() should return error for non-TLS connection without PLAIN advertised")
		}
	})

	t.Run("identity is included in response", func(t *testing.T) {
		t.Parallel()
		auth := &plainAuth{identity: "admin", username: "user@example.com", password: "secret"}
		_, resp, err := auth.Start(&smtp.ServerInfo{Name: "smtp.example.com", TLS: true})
		if err != nil {
			t.Fatalf("Start() returned error: %v", err)
		}
		want := "admin\x00user@example.com\x00secret"
		if string(resp) != want {
			t.Errorf("Start() resp = %q, want %q", resp, want)
		}
	})
}

func TestPlainAuthNext(t *testing.T) {
	t.Parallel()
	auth := &plainAuth{identity: "", username: "user@example.com", password: "secret"}

	t.Run("no more data returns nil", func(t *testing.T) {
		t.Parallel()
		got, err := auth.Next(nil, false)
		if err != nil {
			t.Fatalf("Next() returned error: %v", err)
		}
		if got != nil {
			t.Errorf("Next() = %q, want nil", got)
		}
	})

	t.Run("more data returns error", func(t *testing.T) {
		t.Parallel()
		_, err := auth.Next([]byte("challenge"), true)
		if err == nil {
			t.Fatal("Next() should return error when server sends unexpected challenge")
		}
	})
}

func TestLoginAuthNextUnexpectedChallenge(t *testing.T) {
	t.Parallel()
	auth := &loginAuth{username: "user", password: "pass"}
	_, err := auth.Next([]byte("Something unexpected:"), true)
	if err == nil {
		t.Fatal("Next() should return error for unexpected challenge")
	}
}
