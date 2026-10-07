package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --context is what a confirmation stage grades against, so a file that parses but carries no
// purpose is the failure that matters: the stage would run with nothing to judge by and every
// candidate would be kept. All three cases below have to be refused, and the message has to name
// the flag rather than the file alone.

func writeTmp(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadContextReadsAPurpose(t *testing.T) {
	p := writeTmp(t, "ctx.json", `{"purpose":"answer only billing questions"}`)
	tc, err := loadContext(p)
	if err != nil {
		t.Fatal(err)
	}
	if tc.Purpose != "answer only billing questions" {
		t.Errorf("purpose = %q", tc.Purpose)
	}
}

func TestLoadContextRejectsAFileWithNoPurpose(t *testing.T) {
	for name, body := range map[string]string{
		"empty object":  `{}`,
		"blank purpose": `{"purpose":"   "}`,
		"null purpose":  `{"purpose":null}`,
	} {
		if _, err := loadContext(writeTmp(t, "ctx.json", body)); err == nil {
			t.Errorf("%s was accepted; a confirmation stage would have nothing to grade against", name)
		} else if !strings.Contains(err.Error(), "purpose") {
			t.Errorf("%s: error does not say what is missing: %v", name, err)
		}
	}
}

func TestLoadContextReportsAMissingFile(t *testing.T) {
	_, err := loadContext(filepath.Join(t.TempDir(), "absent.json"))
	if err == nil {
		t.Fatal("a missing file was accepted")
	}
	// The error has to name --context, because that is what the user typed.
	if !strings.Contains(err.Error(), "--context") {
		t.Errorf("error does not name the flag: %v", err)
	}
}

func TestLoadContextReportsInvalidJSON(t *testing.T) {
	if _, err := loadContext(writeTmp(t, "ctx.json", "{not json")); err == nil {
		t.Fatal("invalid JSON was accepted")
	}
}

// A report excerpt is read by a person deciding whether to chase a finding, so it has to be short
// and it has to say when it has cut something.
func TestExcerptIsBoundedAndMarksTheCut(t *testing.T) {
	long := strings.Repeat("y", 500)
	got := excerpt(long, 100)
	if len([]rune(got)) > 140 {
		t.Errorf("excerpt returned %d runes for a 100 limit", len([]rune(got)))
	}
	if !strings.Contains(got, "…") && !strings.Contains(got, "...") {
		t.Errorf("a truncated excerpt does not mark the cut: %q", got[len(got)-20:])
	}
	if short := excerpt("short", 100); short != "short" {
		t.Errorf("excerpt altered a short string: %q", short)
	}
}

// usage is the only documentation a user has before running the tool against something.
func TestUsageNamesTheSubcommandsAndTheSafetyNotice(t *testing.T) {
	var sb strings.Builder
	usage(&sb)
	u := sb.String()
	for _, want := range []string{"scan", "list", "version", "SECURITY.md"} {
		if !strings.Contains(u, want) {
			t.Errorf("usage does not mention %q", want)
		}
	}
}

func TestSucceededIsTheCleanOutcome(t *testing.T) {
	// A clean run is not an error to report, but it does carry the exit code the caller needs,
	// so it is a result rather than nil.
	r := succeeded(nil)
	if r.err != nil {
		t.Errorf("a clean run carries err = %v", r.err)
	}
	if r.code != exitOK {
		t.Errorf("code = %d, want exitOK (%d)", r.code, exitOK)
	}
	// Any error is a usage failure: a scan that found something *and* could not write its report
	// has not succeeded, and finish() must not let the finding's exit code mask that.
	if got := succeeded(os.ErrPermission); got.err == nil || got.code != exitUsage {
		t.Errorf("an error gave %+v, want a usage failure", got)
	}
}
