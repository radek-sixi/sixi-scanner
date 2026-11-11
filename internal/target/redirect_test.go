package target

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// received is what a server was sent.
type received struct {
	mu    sync.Mutex
	hits  int
	key   string
	body  string
	paths []string
}

func (r *received) handler(reply string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.hits++
		r.key = req.Header.Get("X-Api-Key")
		r.body = string(raw)
		r.paths = append(r.paths, req.URL.Path)
		r.mu.Unlock()
		_, _ = w.Write([]byte(reply))
	}
}

// A 307 is re-sent with its body and its headers. Followed to another host, it hands that host the
// prompt and the credential that came with it.
func TestARedirectToAnotherHostIsNotFollowed(t *testing.T) {
	var elsewhere received
	other := httptest.NewServer(elsewhere.handler(`{"ok":true}`))
	defer other.Close()

	// The same listener under another name: to the client it is another host.
	otherURL := strings.Replace(other.URL, "127.0.0.1", "localhost", 1)
	if otherURL == other.URL {
		t.Skip("the test server is not on 127.0.0.1, so it cannot be addressed as a second host")
	}

	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL+"/collect", http.StatusTemporaryRedirect)
	}))
	defer front.Close()

	cfg := Config{URL: front.URL, Timeout: 9 * time.Second, Headers: map[string]string{"X-Api-Key": "secret-key"}}
	_, _, _, err := post(context.Background(), cfg, []byte(`{"prompt":"the payload"}`), "application/json")
	if err == nil {
		t.Fatal("the redirect was followed without complaint")
	}
	if !strings.Contains(err.Error(), "another host") {
		t.Errorf("the error does not say why: %v", err)
	}
	if elsewhere.hits != 0 {
		t.Errorf("the other host received %d request(s): key %q, body %q", elsewhere.hits, elsewhere.key, elsewhere.body)
	}
}

// A redirect that stays on the host is ordinary — a missing trailing slash, a versioned path — and
// is followed with everything the request carried.
func TestARedirectOnTheSameHostIsFollowed(t *testing.T) {
	var got received
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/chat", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/v1/chat/", http.StatusPermanentRedirect)
	})
	mux.HandleFunc("/v1/chat/", got.handler(`{"ok":true}`))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := Config{URL: srv.URL + "/v1/chat", Timeout: 9 * time.Second, Headers: map[string]string{"X-Api-Key": "secret-key"}}
	status, body, _, err := post(context.Background(), cfg, []byte(`{"prompt":"the payload"}`), "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || body != `{"ok":true}` {
		t.Errorf("status %d, body %q", status, body)
	}
	if got.hits != 1 || got.key != "secret-key" || got.body != `{"prompt":"the payload"}` {
		t.Errorf("the redirected request arrived as hits=%d key=%q body=%q", got.hits, got.key, got.body)
	}
}

func TestARedirectLoopStops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	_, _, _, err := post(context.Background(), Config{URL: srv.URL + "/loop", Timeout: 9 * time.Second}, []byte(`{}`), "application/json")
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("a redirect loop ended with %v, want it stopped and named", err)
	}
}
