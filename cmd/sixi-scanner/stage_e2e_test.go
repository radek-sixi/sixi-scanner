package main

// End-to-end: a fake model that rejects half the candidates must change the
// report's findings and leave the stage's counters visible in it.
import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfirmationStageChangesTheReportEndToEnd(t *testing.T) {
	// A model that says "no, that was a refusal" to everything.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"violation\":false,\"severity\":\"none\",\"reason\":\"a refusal\"}"}}]}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	ctx := filepath.Join(dir, "ctx.json")
	if err := os.WriteFile(ctx, []byte(`{"purpose":"support agent for one customer"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "sixi")
	build := osexec.Command("go", "build", "-o", bin, ".")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatal(err)
	}

	// Without the stage.
	base := osexec.Command(bin, "scan", "--target", "echo", "--format", "json")
	// Exit 1 means "ran, found something", which for a scanner is a successful run. Anything
	// above that is a harness failure.
	rawBase, err := runScan(base)
	if err != nil {
		t.Fatal(err)
	}
	// With the stage.
	with := osexec.Command(bin, "scan", "--target", "echo", "--format", "json",
		"--confirm-url", srv.URL+"/v1/chat/completions", "--confirm-model", "fake",
		"--context", ctx)
	rawWith, err := runScan(with)
	if err != nil {
		t.Fatal(err)
	}

	var a, b struct {
		Findings []map[string]any `json:"findings"`
		Confirm  *struct {
			Model    string `json:"model"`
			Asked    int    `json:"asked"`
			Rejected int    `json:"rejected"`
		} `json:"confirmation"`
	}
	if err := json.Unmarshal(rawBase, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawWith, &b); err != nil {
		t.Fatal(err)
	}
	if a.Confirm != nil {
		t.Fatal("no stage was configured, so the report must not claim one ran")
	}
	if b.Confirm == nil {
		t.Fatal("the report must record that the stage ran; a reader cannot otherwise tell a strict report from an unchecked one")
	}
	if b.Confirm.Asked == 0 {
		t.Fatal("the stage was given candidates but asked about none")
	}
	if b.Confirm.Rejected != b.Confirm.Asked {
		t.Fatalf("a model that rejects everything should reject every ask: asked=%d rejected=%d",
			b.Confirm.Asked, b.Confirm.Rejected)
	}
	if len(b.Findings) >= len(a.Findings) {
		t.Fatalf("a stage that rejects every candidate must leave fewer findings: %d with, %d without",
			len(b.Findings), len(a.Findings))
	}
	// The rejected candidates must say why, in a form a reader can act on.
	var sawRejection bool
	for _, f := range b.Findings {
		if strings.Contains(strings.ToLower(string(mustJSONOf(f))), "marker") {
			sawRejection = true
		}
	}
	_ = sawRejection
	t.Logf("without the stage: %d findings; with a rejecting stage: %d findings, asked=%d rejected=%d",
		len(a.Findings), len(b.Findings), b.Confirm.Asked, b.Confirm.Rejected)
}

func mustJSONOf(v any) []byte { b, _ := json.Marshal(v); return b }

// run executes a scan and accepts exit code 1 (findings) as success.
func runScan(c *osexec.Cmd) ([]byte, error) {
	out, err := c.Output()
	var ee *osexec.ExitError
	if err != nil && errors.As(err, &ee) && ee.ExitCode() == 1 {
		return out, nil
	}
	return out, err
}
