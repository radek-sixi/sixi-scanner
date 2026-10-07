package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/report"
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// A report file is the artifact a CI job archives and a reviewer opens. Two failure modes matter:
// writing nothing while reporting success, and silently choosing a format the caller did not ask
// for.

func TestWriteFileCreatesMissingDirectories(t *testing.T) {
	// --out reports/a/scan.json must not fail because reports/ does not exist; that is the shape
	// every CI job uses.
	path := filepath.Join(t.TempDir(), "reports", "nested", "scan.json")
	if err := writeFile(path, "json", sampleScan()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
		t.Errorf("the file is not the json report:\n%s", b)
	}
}

func TestWriteFileInfersTheFormatFromTheExtension(t *testing.T) {
	// A caller who names the file and omits --format expects the extension to be honoured.
	for ext, probe := range map[string]string{
		"json":  `"findings"`,
		"md":    "#",
		"sarif": "sarif",
	} {
		path := filepath.Join(t.TempDir(), "scan."+ext)
		if err := writeFile(path, "", sampleScan()); err != nil {
			t.Fatalf("%s: %v", ext, err)
		}
		b, _ := os.ReadFile(path)
		if !strings.Contains(string(b), probe) {
			t.Errorf(".%s produced the wrong format:\n%s", ext, b)
		}
	}
}

// An unrecognised extension falls back to JSON rather than failing, because the caller named a
// path and got a report written to it. Pinned here because it is surprising enough to be worth
// knowing about: `--out scan.pdf` produces JSON in a file called scan.pdf. It is left as it is —
// callers rely on the fallback, and refusing would turn a working invocation into an error — but a
// reader of this test should not be surprised by it later.
func TestWriteFileFallsBackToJSONForAnUnknownExtension(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.pdf")
	if err := writeFile(path, "", sampleScan()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
		t.Errorf("the fallback did not write json:\n%s", b)
	}
}

// An explicit format beats the extension: the caller asked for it.
func TestWriteFilePrefersAnExplicitFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := writeFile(path, "markdown", sampleScan()); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if strings.Contains(string(b), `"findings"`) {
		t.Errorf("--format markdown was overridden by the .json extension:\n%s", b)
	}
}

func TestWriteFileReportsAnUnwritablePath(t *testing.T) {
	// A path under a file rather than a directory: the error has to say so rather than panic.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(blocker, "scan.json"), "json", sampleScan()); err == nil {
		t.Error("an unwritable path was accepted")
	}
}

// A clean scan's summary is the line a CI log is judged on, so it has to state the coverage as well
// as the result: "no findings" from a run that tested nothing is a different claim.
func TestCleanScanSummaryNamesTheTarget(t *testing.T) {
	s := &report.Scan{Attempts: 21, Target: "json https://agent.example/v1/chat/completions"}
	got := s.String()
	for _, want := range []string{"no findings", "21", "agent.example"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary = %q, missing %q", got, want)
		}
	}
}

func TestSummaryCountsEverySeverityThatOccurred(t *testing.T) {
	s := &report.Scan{Attempts: 5, Target: "echo", Findings: []report.Finding{
		{Severity: tech.SeverityCritical, TechniqueID: "a", Title: "t"},
		{Severity: tech.SeverityHigh, TechniqueID: "b", Title: "t"},
		{Severity: tech.SeverityHigh, TechniqueID: "c", Title: "t"},
	}}
	got := s.String()
	for _, want := range []string{"3 finding(s)", "1 critical", "2 high"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary = %q, missing %q", got, want)
		}
	}
	// A severity with no findings must not be listed as though it had some.
	if strings.Contains(got, "low") || strings.Contains(got, "info") {
		t.Errorf("summary lists a severity that did not occur: %q", got)
	}
}
