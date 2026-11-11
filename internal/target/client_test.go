package target

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// countingTLSServer is a TLS endpoint with a self-signed certificate that counts the connections
// opened to it.
func countingTLSServer(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var opened atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			opened.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, &opened
}

// An --insecure scan used to build a transport for every request. Nothing was reused, so each
// prompt opened a connection of its own and left it idle behind it.
func TestAnInsecureScanReusesItsConnection(t *testing.T) {
	srv, opened := countingTLSServer(t)
	// A timeout no other test uses, so this test gets a client and a pool of its own.
	cfg := Config{URL: srv.URL, Insecure: true, Timeout: 7 * time.Second}

	const sends = 12
	for i := 0; i < sends; i++ {
		status, _, _, err := post(context.Background(), cfg, []byte(`{}`), "application/json")
		if err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if status != http.StatusOK {
			t.Fatalf("send %d: status %d", i, status)
		}
	}
	if n := opened.Load(); n != 1 {
		t.Errorf("%d sends opened %d connections, want 1", sends, n)
	}
}

// The client belongs to the configuration, not to the process: a verified scan must not be handed
// the transport that skips verification, in whichever order the two are built.
func TestSkippingVerificationDoesNotLeakIntoAVerifiedClient(t *testing.T) {
	srv, _ := countingTLSServer(t)

	insecure := Config{URL: srv.URL, Insecure: true, Timeout: 8 * time.Second}
	if _, _, _, err := post(context.Background(), insecure, []byte(`{}`), "application/json"); err != nil {
		t.Fatalf("the insecure send failed: %v", err)
	}
	verified := Config{URL: srv.URL, Timeout: 8 * time.Second}
	if _, _, _, err := post(context.Background(), verified, []byte(`{}`), "application/json"); err == nil {
		t.Fatal("a verified send accepted a self-signed certificate")
	}
	if clientFor(insecure) == clientFor(verified) {
		t.Error("the two configurations share a client")
	}
	if clientFor(insecure) != clientFor(insecure) {
		t.Error("the same configuration was given two clients")
	}
}
