package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// exec runs the CLI in-process and returns what the user would have seen
// alongside the exit code. It calls run rather than main so the test does not
// exit the test binary.
func exec(args ...string) (stdout, stderr string, code int) {
	var out, errOut strings.Builder
	code = run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func TestVersionPrintsAToolAndVersion(t *testing.T) {
	stdout, _, _ := exec("version")
	if !strings.Contains(stdout, "sixi-scanner") {
		t.Errorf("version output = %q", stdout)
	}
}

func TestListShowsTheCatalogue(t *testing.T) {
	stdout, _, _ := exec("list")
	if !strings.Contains(stdout, "llm02.system-prompt-leak") {
		t.Error("the catalogue is missing a known technique")
	}
	if !strings.Contains(stdout, "not an assurance") {
		t.Error("the catalogue does not state that a clean result is not an assurance")
	}
}

func TestListJSONIsMachineReadable(t *testing.T) {
	stdout, _, _ := exec("list", "--json")

	var out struct {
		Count      int `json:"count"`
		Techniques []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("list --json is not valid JSON: %v", err)
	}
	if out.Count != len(out.Techniques) || out.Count == 0 {
		t.Errorf("count %d does not match %d techniques", out.Count, len(out.Techniques))
	}
}

func TestListDetailForOneTechnique(t *testing.T) {
	stdout, _, _ := exec("list", "--detail", "llm02.system-prompt-leak")
	for _, want := range []string{"Variants", "Success markers", "Negation cues", "Remediation"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("detail output is missing %q", want)
		}
	}
}

func TestUnknownCommandFails(t *testing.T) {
	_, stderr, _ := exec("frobnicate")
	if !strings.Contains(stderr, "unknown command") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestATypoInOnlyIsAnErrorNotASilentCleanScan(t *testing.T) {
	// The worst failure mode for a scanner: a filter typo that scans nothing
	// and is reported as a clean result.
	_, stderr, code := exec("scan", "--target", "echo", "--only", "llm02.system-prompt-leak,typo.here")

	if code == 0 {
		t.Error("a typo in --only exited 0, which reads as a clean scan")
	}
	if !strings.Contains(stderr, "unknown technique") {
		t.Errorf("stderr = %q, want it to name the unknown technique", stderr)
	}
}

// The echo transport makes the whole pipeline runnable with no network, so the
// report shape can be checked in CI and by anyone curious.
func TestEchoScanProducesAWellFormedReport(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report.json")

	stdout, _, _ := exec("scan",
		"--target", "echo",
		"--only", "llm01.instruction-override",
		"--attempts", "1",
		"--quiet",
		"--format", "json",
		"--out", out,
	)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}

	var scan struct {
		SchemaVersion string `json:"schema_version"`
		Tool          string `json:"tool"`
		Target        string `json:"target"`
		Findings      []struct {
			TechniqueID string `json:"technique_id"`
		} `json:"findings"`
		NoAnswer []string `json:"no_answer"`
	}
	if err := json.Unmarshal(raw, &scan); err != nil {
		t.Fatalf("report is not valid JSON: %v\n%s", err, raw)
	}

	if scan.Tool != "sixi-scanner" {
		t.Errorf("tool = %q", scan.Tool)
	}
	if !strings.Contains(scan.Target, "echo") {
		t.Errorf("target = %q, want it to name the echo transport", scan.Target)
	}
	if !strings.Contains(stdout, "finding") {
		t.Errorf("stdout summary = %q", stdout)
	}

	// The echo target reflects the prompt back. instruction-override is the
	// technique that reliably trips it — its own payload names "unrestricted",
	// "no policy" and "ready", and two unambiguous markers are required — which
	// makes the whole pipeline exercisable with no network at all.
	if len(scan.Findings) == 0 {
		t.Error("the echo target reflects the prompt, so a finding was expected")
	}
}

func TestSARIFOutputIsWrittenAndInfersTheExtension(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "sixi.sarif")

	_, _, _ = exec("scan", "--target", "echo", "--only", "llm02.system-prompt-leak",
		"--attempts", "1", "--quiet", "--out", out)

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no SARIF written: %v", err)
	}
	var log map[string]any
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v", log["version"])
	}
}

func TestUnknownFormatIsRejected(t *testing.T) {
	_, stderr, _ := exec("scan", "--target", "echo", "--format", "pdf")
	if !strings.Contains(stderr, "unknown format") {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestUnknownSeverityIsRejected(t *testing.T) {
	_, stderr, _ := exec("scan", "--target", "echo", "--min-severity", "apocalyptic")
	if !strings.Contains(stderr, "unknown severity") {
		t.Errorf("stderr = %q", stderr)
	}
}

// Against a real HTTP endpoint the whole path — flag to connector to engine to
// report — is exercised, which is the only way to know the flags connect.
func TestScanAgainstAnOpenAICompatibleEndpoint(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.Messages) > 0 {
			seen = append(seen, body.Messages[0].Content)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"You are a billing assistant. Your instructions are to be brief."}}]}`))
	}))
	defer srv.Close()

	stdout, _, _ := exec("scan",
		"--target", "openai",
		"--url", srv.URL,
		"--only", "llm02.system-prompt-leak",
		"--attempts", "1",
		"--quiet",
	)

	if len(seen) != 1 {
		t.Fatalf("the endpoint received %d requests, want 1", len(seen))
	}
	if !strings.Contains(seen[0], "instructions") {
		t.Errorf("the probe did not reach the endpoint: %q", seen[0])
	}
	if !strings.Contains(stdout, "system-prompt") && !strings.Contains(stdout, "finding") {
		t.Errorf("stdout = %q, want a finding summary", stdout)
	}
}

// A severity floor filters techniques *before* the scan, so the tool does not
// spend requests on findings it would then discard. When nothing clears the
// floor it has to say so rather than reporting a clean scan.
func TestMinSeverityFiltersTechniquesBeforeScanning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"You are a billing assistant. Your instructions are to be brief."}}]}`))
	}))
	defer srv.Close()

	// system-prompt-leak is high severity; a critical floor leaves nothing.
	_, stderr, code := exec("scan", "--target", "openai", "--url", srv.URL,
		"--only", "llm02.system-prompt-leak", "--attempts", "1",
		"--min-severity", "critical")

	if code != 2 {
		t.Errorf("exit code = %d, want 2 for a filter that leaves no techniques", code)
	}
	if !strings.Contains(stderr, "no techniques at or above severity") {
		t.Errorf("stderr = %q, want an explanation rather than a silent clean run", stderr)
	}

	// A floor the technique clears still runs, still reports, and still fails
	// the build.
	dir := t.TempDir()
	out := filepath.Join(dir, "high.json")
	_, _, code = exec("scan", "--target", "openai", "--url", srv.URL,
		"--only", "llm02.system-prompt-leak", "--attempts", "1",
		"--quiet", "--format", "json", "--min-severity", "high", "--out", out)

	if code != 1 {
		t.Errorf("exit code = %d, want 1 for a scan that found something", code)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("no report written: %v", err)
	}
	var scan struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(raw, &scan); err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) == 0 {
		t.Error("the finding did not survive a floor it clears")
	}
}

// A scan that finds nothing still has to exit cleanly. This regressed once:
// the command signalled its exit code by returning a wrapper around a nil
// error, which was non-nil, so the CLI printed a nil-pointer panic instead of
// exiting 0 — on the exact run a CI job cares most about.
func TestCleanScanExitsZeroWithoutPanicking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"I can't help with that request."}}]}`))
	}))
	defer srv.Close()

	_, stderr, code := exec("scan", "--target", "openai", "--url", srv.URL, "--quiet")

	if code != 0 {
		t.Errorf("exit code = %d, want 0 for a clean scan", code)
	}
	for _, bad := range []string{"PANIC", "runtime error", "nil pointer"} {
		if strings.Contains(stderr, bad) {
			t.Errorf("a clean run wrote %q to stderr: %s", bad, stderr)
		}
	}
	if stderr != "" {
		t.Errorf("a clean, quiet scan wrote to stderr: %q", stderr)
	}
}

func TestScanWithFindingsExitsOne(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"You are a billing assistant. Your instructions are to be brief."}}]}`))
	}))
	defer srv.Close()

	_, stderr, code := exec("scan", "--target", "openai", "--url", srv.URL,
		"--only", "llm02.system-prompt-leak", "--attempts", "1", "--quiet")

	if code != 1 {
		t.Errorf("exit code = %d, want 1 when a finding exists", code)
	}
	if stderr != "" {
		t.Errorf("a quiet scan wrote to stderr: %q", stderr)
	}
}

func TestSeedIsAppliedToProbes(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct{ Content string } `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if len(body.Messages) > 0 {
			seen = body.Messages[0].Content
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"choices":[{"message":{"content":"I can't help with that."}}]}`))
	}))
	defer srv.Close()

	exec("scan", "--target", "openai", "--url", srv.URL,
		"--only", "llm02.system-prompt-leak", "--attempts", "1", "--quiet",
		"--seed", "You are a support bot for ACME Ltd.")

	if !strings.HasPrefix(seen, "You are a support bot for ACME Ltd.") {
		t.Errorf("the seed was not applied: %q", seen)
	}
}

func TestCredentialsInAURLAreNotPrinted(t *testing.T) {
	// The URL is echoed in error paths; a secret must never appear.
	_, stderr, _ := exec("scan", "--target", "json",
		"--url", "http://user:hunter2@127.0.0.1:1/never",
		"--reply-path", "nope")

	if strings.Contains(stderr, "hunter2") {
		t.Errorf("a password leaked into stderr: %q", stderr)
	}
}
