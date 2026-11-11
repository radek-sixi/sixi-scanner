package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// --confirm-min-severity takes a severity name, and a name it does not know ranks as zero — which
// is the floor "none". A typo therefore ran the whole scan with the most permissive bar there is.
// It is refused before anything is sent.
func TestAMistypedConfirmFloorIsRefusedBeforeTheScan(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(okCompletion))
	}))
	defer srv.Close()

	ctxFile := filepath.Join(t.TempDir(), "ctx.json")
	if err := os.WriteFile(ctxFile, []byte(`{"purpose":"support agent for one customer"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, stderr, code := exec("scan", "--url", srv.URL, "--quiet",
		"--confirm-url", srv.URL, "--confirm-model", "judge", "--context", ctxFile,
		"--confirm-min-severity", "hgih")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "hgih") || !strings.Contains(stderr, "none, low, medium, high, critical") {
		t.Errorf("the error does not name the value and the choices: %q", stderr)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests were sent before the flag was refused", n)
	}
}
