//go:build !scanner

package detector

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerTransport_SetsAuthorizationHeader(t *testing.T) {
	t.Parallel()

	const token = "ghp_test1234567890"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer " + token
		if got != want {
			t.Errorf("Authorization header = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := &http.Client{
		Transport: &bearerTransport{token: token, base: http.DefaultTransport},
	}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestBearerTransport_ClonesRequest(t *testing.T) {
	t.Parallel()

	const token = "ghp_clonetest"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &bearerTransport{token: token, base: http.DefaultTransport}

	req, err := http.NewRequest(http.MethodGet, ts.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("X-Custom", "original")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip error: %v", err)
	}
	defer resp.Body.Close()

	// The original request must not have the Authorization header injected.
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("original request Authorization header = %q, want empty (request was mutated)", got)
	}

	// The original X-Custom header should still be present and unchanged.
	if got := req.Header.Get("X-Custom"); got != "original" {
		t.Errorf("original request X-Custom header = %q, want %q", got, "original")
	}
}

func TestNewBearerClient_ReturnsValidClient(t *testing.T) {
	t.Parallel()

	const token = "ghp_integrationtest"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		want := "Bearer " + token
		if got != want {
			t.Errorf("Authorization header = %q, want %q", got, want)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// newBearerClient uses http.DefaultTransport, so it can reach the test server.
	client := newBearerClient(token)
	if client == nil {
		t.Fatal("newBearerClient returned nil")
	}

	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}
