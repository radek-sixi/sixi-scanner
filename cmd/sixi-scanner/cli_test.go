package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/radek-sixi/sixi-scanner/internal/report"
)

// Asking for help is not a failed command. It exited 2 and printed "flag: help requested" as an
// error, so a script that ran --help to check the tool was installed concluded that it was not.
func TestHelpExitsZeroAndReportsNoError(t *testing.T) {
	for _, args := range [][]string{{"scan", "--help"}, {"scan", "-h"}, {"list", "--help"}} {
		_, stderr, code := exec(args...)
		if code != exitOK {
			t.Errorf("%v exited %d, want %d", args, code, exitOK)
		}
		if strings.Contains(stderr, "help requested") {
			t.Errorf("%v reported its own help as an error: %q", args, stderr)
		}
	}
	// A flag that does not exist is still a usage error.
	if _, _, code := exec("scan", "--no-such-flag"); code != exitUsage {
		t.Errorf("an unknown flag exited %d, want %d", code, exitUsage)
	}
}

// The format was only looked at when the report was written — after the scan. A typo ran every
// technique against the target and then had nowhere to put the result.
func TestAnUnknownFormatIsRefusedBeforeTheScan(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(okCompletion))
	}))
	defer srv.Close()

	_, stderr, code := exec("scan", "--url", srv.URL, "--quiet", "--format", "yaml")
	if code != exitUsage {
		t.Errorf("exit code = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, `unknown format "yaml"`) {
		t.Errorf("the error does not name the format: %q", stderr)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("%d requests were sent before the format was refused", n)
	}
}

// A report holds what the agent should not have said. It is written for its owner.
func TestAReportFileIsReadableByItsOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not carry this meaning on Windows")
	}
	path := filepath.Join(t.TempDir(), "out", "report.json")
	if err := writeFile(path, "json", &report.Scan{Tool: toolName}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("report mode = %o, want 600", got)
	}
}
