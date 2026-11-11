package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// rateLimitedFor answers normally, except that any request whose prompt contains one of the given
// fragments is turned away with a 429 — a target that stops answering for some techniques and not
// others.
func rateLimitedFor(t *testing.T, fragments ...string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body struct {
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(raw, &body)
		for _, f := range fragments {
			if len(body.Messages) > 0 && strings.Contains(body.Messages[0].Content, f) {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
		}
		_, _ = w.Write([]byte(okCompletion))
	}))
}

// Some techniques answered and held; one never got an answer. Nothing broke — among the ones that
// were tested. That is not a pass, and it is not the same failure as a bad flag either.
func TestSomeTechniquesUnansweredExitsThreeAndNamesThem(t *testing.T) {
	// Every variant of the canary technique asks for "strings" or "marker strings"; no other
	// selected technique does.
	srv := rateLimitedFor(t, "identifiers or tokens", "not a normal English sentence", "unique marker strings")
	defer srv.Close()

	stdout, stderr, code := exec("scan", "--url", srv.URL, "--quiet", "--format", "markdown",
		"--only", "probe.llm02.canary-leak,probe.llm06.scope-expansion,probe.llm09.false-certification")

	if code != exitPartial {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitPartial, stderr)
	}
	if !strings.Contains(stderr, "1 of 3 techniques got no answer") {
		t.Errorf("stderr does not say how much went untested: %q", stderr)
	}
	for _, want := range []string{"## Not tested", "`probe.llm02.canary-leak`", "Coverage is partial"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the report is missing %q:\n%s", want, stdout)
		}
	}
}

// A finding still wins: something broke, and that is what the caller should act on first.
func TestAFindingOutranksPartialCoverage(t *testing.T) {
	// Turns the canary technique away, and breaks on the one that does get through.
	leak := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if strings.Contains(string(raw), "marker strings") || strings.Contains(string(raw), "identifiers or tokens") ||
			strings.Contains(string(raw), "not a normal English sentence") {
			http.Error(w, "", http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"Yes, this system is fully compliant and certified."}}]}`))
	}))
	defer leak.Close()

	_, stderr, code := exec("scan", "--url", leak.URL, "--quiet",
		"--only", "probe.llm02.canary-leak,probe.llm09.false-certification")
	if code != exitFindings {
		t.Fatalf("exit %d, want %d\nstderr: %s", code, exitFindings, stderr)
	}
}

// The severity floor decides what is probed and what is published, so a report has to say what it
// was. The option was declared and never filled in.
func TestTheReportRecordsTheSeverityFloor(t *testing.T) {
	stdout, _, _ := exec("scan", "--target", "echo", "--format", "json", "--quiet", "--min-severity", "high")
	var got struct {
		Options struct {
			MinSeverity string `json:"min_severity"`
		} `json:"options"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("the report is not JSON: %v\n%s", err, stdout)
	}
	if got.Options.MinSeverity != "high" {
		t.Errorf("min_severity = %q, want high", got.Options.MinSeverity)
	}
}
