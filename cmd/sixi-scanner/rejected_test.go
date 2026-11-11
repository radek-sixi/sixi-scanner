package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The CI case this exists for: the token expired, or the URL is missing its path, and every request
// comes back with an error status. That scan assessed nothing and must not exit 0.
func TestAnEndpointThatRejectsEveryRequestIsNotAPass(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
		body   string
	}{
		{"an expired token", http.StatusUnauthorized, `{"detail":"Not authenticated"}`},
		{"a wrong path", http.StatusNotFound, `<html><body>404 page not found</body></html>`},
		{"a rate limiter", http.StatusTooManyRequests, `{"error":"rate limit exceeded"}`},
		{"a broken upstream", http.StatusBadGateway, ``},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(c.status)
			_, _ = w.Write([]byte(c.body))
		}))
		stdout, stderr, code := exec("scan", "--url", srv.URL, "--quiet")
		srv.Close()

		if code != exitUsage {
			t.Errorf("%s: exit %d, want %d; stdout=%q", c.name, code, exitUsage, stdout)
		}
		if !strings.Contains(stderr, "nothing was assessed") {
			t.Errorf("%s: the reason is not stated: %q", c.name, stderr)
		}
	}
}
