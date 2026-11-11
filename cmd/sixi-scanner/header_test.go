package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

const okCompletion = `{"choices":[{"message":{"content":"I can only help with billing."}}]}`

// Every --header has to arrive. The flag used to be a plain string, so the last one replaced the
// ones before it: the credential was dropped, the tenant was sent, and the scan ran unauthenticated.
func TestEveryRepeatedHeaderReachesTheTarget(t *testing.T) {
	var (
		once sync.Once
		got  http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		once.Do(func() { got = r.Header.Clone() })
		_, _ = w.Write([]byte(okCompletion))
	}))
	defer srv.Close()

	_, stderr, code := exec("scan", "--url", srv.URL, "--quiet",
		"--only", "probe.llm02.system-prompt-leak", "--attempts", "1",
		"--header", "Authorization: Bearer tok",
		"--header", "X-Tenant: t1",
		// The older single-value form, with "|" between entries, keeps working alongside.
		"--header", "X-A: 1 | X-B: 2",
		// An optional variable that expanded to nothing is not an error.
		"--header", "")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for name, want := range map[string]string{
		"Authorization": "Bearer tok", "X-Tenant": "t1", "X-A": "1", "X-B": "2",
	} {
		if v := got.Get(name); v != want {
			t.Errorf("%s = %q, want %q", name, v, want)
		}
	}
}

// A header with no name or no separator is a typo, and a typo should cost nothing: it is refused
// before a single request goes out rather than discovered as a 401.
func TestAMalformedHeaderIsRefusedBeforeAnythingIsSent(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write([]byte(okCompletion))
	}))
	defer srv.Close()

	for _, bad := range []string{"Authorization Bearer tok", ": orphan"} {
		_, stderr, code := exec("scan", "--url", srv.URL, "--quiet", "--header", bad)
		if code != exitUsage {
			t.Errorf("--header %q: exit %d, want %d", bad, code, exitUsage)
		}
		if !strings.Contains(stderr, "Name: value") {
			t.Errorf("--header %q: the error does not say what was expected: %q", bad, stderr)
		}
	}
	if n := atomic.LoadInt32(&hits); n != 0 {
		t.Errorf("%d request(s) were sent before the bad header was noticed", n)
	}
}
