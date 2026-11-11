package main

import (
	"strings"
	"testing"

	"github.com/radek-sixi/sixi-scanner/internal/tech/baseline"
)

// An export is only useful if it is the technique. The Go form left out the multi-turn payloads,
// the regex markers and the scoring switches, so what it wrote for a sequence technique compiled
// and could send nothing, and a technique whose evidence was a pattern came out without it.
func TestGoExportCarriesEveryFieldATechniqueSets(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range collect(baseline.Registry()) {
		out := capture(t, "--format", "go", "--only", r.ID)
		for field, set := range map[string]bool{
			"Variants:":       len(r.Variants) > 0,
			"Sequence:":       len(r.Sequence) > 0,
			"Markers:":        len(r.Markers) > 0,
			"RegexMarkers:":   len(r.RegexMarkers) > 0,
			"RequireAll:":     r.RequireAll,
			"ClaimCheck:":     r.ClaimCheck,
			"RelayCheck:":     r.RelayCheck,
			"SkipRecitation:": r.SkipRecitation,
		} {
			has := strings.Contains(out, "\t\t"+field)
			if has != set {
				t.Errorf("%s: %s written = %v, set on the technique = %v", r.ID, field, has, set)
			}
			if set {
				seen[field] = true
			}
		}
		if strings.Contains(out, "[]string{}") {
			t.Errorf("%s: an empty list was written, which says the technique has none:\n%s", r.ID, out)
		}
	}
	// If the baseline stops using one of these, this test stops covering it.
	for _, field := range []string{"Sequence:", "RegexMarkers:", "RequireAll:", "ClaimCheck:", "RelayCheck:", "SkipRecitation:"} {
		if !seen[field] {
			t.Errorf("no shipped technique sets %s, so its export is untested here", field)
		}
	}
}

// A pattern is written so that it reads back as the same pattern.
func TestGoExportEscapesARegexMarker(t *testing.T) {
	out := capture(t, "--format", "go", "--only", "probe.llm02.credential-elicitation")
	if !strings.Contains(out, `RegexMarkers: []string{"\\bsk-[a-z0-9_-]{16,}"}`) {
		t.Errorf("the regex marker was not written as a Go string literal:\n%s", out)
	}
}

// Compare exists to catch a change that alters what a technique does. Each of these does, and each
// used to compare as no change at all.
func TestCompareSeesEveryFieldThatChangesBehaviour(t *testing.T) {
	base := record{
		ID: "probe.test", Title: "t", Severity: "high", MinMarkers: 1, Confidence: 0.5,
		Sequence:     [][]string{{"first", "second"}},
		Markers:      []string{"m"},
		RegexMarkers: []string{`\bready\b`},
		RequireAll:   true,
	}
	if !unchanged(base, base) {
		t.Fatal("a record differs from itself")
	}
	cases := []struct {
		name   string
		mutate func(*record)
		says   string
	}{
		{"a rewritten turn", func(r *record) { r.Sequence = [][]string{{"first", "something else"}} }, "conversations"},
		{"a dropped conversation", func(r *record) { r.Sequence = nil }, "1→0 conversations"},
		{"a changed pattern", func(r *record) { r.RegexMarkers = []string{`ready`} }, "regex markers"},
		{"RequireAll", func(r *record) { r.RequireAll = false }, "scoring"},
		{"ClaimCheck", func(r *record) { r.ClaimCheck = true }, "scoring"},
		{"RelayCheck", func(r *record) { r.RelayCheck = true }, "scoring"},
		{"SkipRecitation", func(r *record) { r.SkipRecitation = true }, "scoring"},
	}
	for _, c := range cases {
		changed := base
		c.mutate(&changed)
		if unchanged(base, changed) {
			t.Errorf("%s compared as unchanged", c.name)
		}
		if got := describeChange(base, changed); !strings.Contains(got, c.says) {
			t.Errorf("%s was described as %q, want it to mention %q", c.name, got, c.says)
		}
	}
}
