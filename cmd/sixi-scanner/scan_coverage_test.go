package main

import (
	"strings"
	"sync"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/report"
)

// safeBuffer is a bytes.Buffer that survives the concurrent writes the progress printer makes.
type safeBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func attemptFor(id, note string) report.Attempt {
	a := report.Attempt{TechniqueID: id, Round: 1, Attempt: 1}
	if note != "" {
		a.Response = note
	}
	return a
}

// Headers arrive as one flag value, so the parser has to be forgiving about shape and strict about
// content: a header silently dropped is a request that goes out unauthenticated and fails with a
// 401 that looks like a bad endpoint.
func TestParseHeadersHandlesTheShapesCallersWrite(t *testing.T) {
	got := parseHeaders("Authorization: Bearer tok | X-Trace: abc123")
	if len(got) != 2 {
		t.Fatalf("got %d headers, want 2: %v", len(got), got)
	}
	if got["Authorization"] != "Bearer tok" {
		t.Errorf("Authorization = %q; the space after the colon must be trimmed", got["Authorization"])
	}
	if got["X-Trace"] != "abc123" {
		t.Errorf("X-Trace = %q", got["X-Trace"])
	}
	// A value containing a colon must survive: bearer tokens and URLs both do.
	if v := parseHeaders("X-Url: https://example.test/a")["X-Url"]; v != "https://example.test/a" {
		t.Errorf("a colon inside the value was treated as the separator: %q", v)
	}
}

func TestParseHeadersReturnsNilRatherThanAnEmptyMap(t *testing.T) {
	// nil and an empty map behave differently where this is used: an empty map would be sent as a
	// non-nil header set.
	for name, in := range map[string]string{
		"empty":       "",
		"whitespace":  "   ",
		"no colons":   "just some words",
		"only commas": "a,b,c",
	} {
		if got := parseHeaders(in); got != nil {
			t.Errorf("%s: parseHeaders = %v, want nil", name, got)
		}
	}
}

func TestParseHeadersKeepsTheValidEntriesAroundAMalformedOne(t *testing.T) {
	// A malformed entry must not cost the caller the headers they did write: a dropped
	// Authorization header would surface as a 401 that looks like a bad endpoint.
	got := parseHeaders("Authorization: Bearer tok | no-colon-here | : orphan")
	if got["Authorization"] != "Bearer tok" {
		t.Errorf("a valid header was lost alongside malformed ones: %v", got)
	}
	if _, ok := got["no-colon-here"]; ok {
		t.Errorf("an entry with no separator became a header: %v", got)
	}
}

// firstLine labels an attempt in progress output, and a progress line that spills onto two lines
// breaks the one-line-per-attempt contract the printer maintains.
func TestFirstLineTakesOnlyTheFirst(t *testing.T) {
	for in, want := range map[string]string{
		"one line":             "one line",
		"first\nsecond":        "first",
		"first\nsecond\nthird": "first",
		"":                     "",
		"\nleading newline":    "",
		"trailing\n":           "trailing",
	} {
		if got := firstLine(in); got != want {
			t.Errorf("firstLine(%q) = %q, want %q", in, got, want)
		}
	}
}

// The progress printer is called concurrently, so its output has to stay one line per attempt or
// the transcript becomes unreadable.
func TestProgressPrinterKeepsOneLinePerAttemptUnderConcurrency(t *testing.T) {
	var sb safeBuffer
	printer := progressPrinter(&sb)

	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(i int) {
			for j := 0; j < 25; j++ {
				printer(attemptFor("probe.llm01.example", "r1 a1"))
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
	lines := strings.Split(strings.TrimRight(sb.String(), "\n"), "\n")
	if len(lines) != 100 {
		t.Fatalf("got %d lines for 100 attempts; the printer interleaved", len(lines))
	}
	for _, l := range lines {
		if strings.Count(l, "probe.llm01.example") != 1 {
			t.Errorf("a line carries the wrong number of attempts, so two were interleaved: %q", l)
		}
	}
}
