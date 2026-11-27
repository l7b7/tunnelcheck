package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestNormalizeURL(t *testing.T) {
	u, err := normalizeURL("example.test/path?token=must-not-be-sent")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := u.String(), "https://example.test/path"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := normalizeURL("https://user:pass@example.test/"); err == nil {
		t.Fatal("expected credentials to be rejected")
	}
}

func TestHTTP1Probe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("got method %s", r.Method)
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := probeHTTP1(u, 2*time.Second)
	if !r.Supported || r.HTTP != "HTTP/1.1" || r.Status != http.StatusNoContent {
		t.Fatalf("unexpected probe result: %+v", r)
	}
	if r.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Fatalf("expected safe header observation: %+v", r.Headers)
	}
}

func TestHTTP2Probe(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	r := runProbe(u, "HTTP/2", 2*time.Second, func() *http.Client {
		return &http.Client{Transport: &http2.Transport{TLSClientConfig: srv.Client().Transport.(*http.Transport).TLSClientConfig}, Timeout: 2 * time.Second}
	})
	if !r.Supported || r.HTTP != "HTTP/2.0" || r.TLSALPN != "h2" {
		t.Fatalf("unexpected probe result: %+v", r)
	}
}

func TestCVEPattern(t *testing.T) {
	for _, id := range []string{"CVE-2023-44487", "CVE-1999-0001"} {
		if !cvePattern.MatchString(id) {
			t.Errorf("expected valid CVE ID: %s", id)
		}
	}
	for _, id := range []string{"CVE-23-44487", "2023-44487", "CVE-2023-x"} {
		if cvePattern.MatchString(id) {
			t.Errorf("unexpected valid CVE ID: %s", id)
		}
	}
}

