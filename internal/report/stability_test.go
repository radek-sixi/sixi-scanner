package report

import (
	"strings"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/tech"
)

func scanWith(n int) *Scan {
	s := &Scan{}
	for i := 0; i < n; i++ {
		s.Findings = append(s.Findings, Finding{
			TechniqueID: "probe.llm0" + string(rune('0'+i%10)) + ".example",
			Severity:    tech.SeverityHigh,
			Fingerprint: "fp-" + string(rune('a'+i)),
		})
	}
	return s
}

// StableFingerprintIDs exists so two runs can be diffed, which only works if the list is stable for
// the same set of findings. Order therefore comes from the findings, not from a map iteration.
func TestStableFingerprintIDsFollowTheFindings(t *testing.T) {
	s := scanWith(3)
	got := s.StableFingerprintIDs()
	want := []string{"fp-a", "fp-b", "fp-c"}
	if len(got) != len(want) {
		t.Fatalf("got %d fingerprints, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("fingerprint %d = %q, want %q; the order has to be stable to diff two runs",
				i, got[i], want[i])
		}
	}
	// Calling it twice must not reorder: that is the property a diff depends on.
	again := s.StableFingerprintIDs()
	for i := range got {
		if got[i] != again[i] {
			t.Fatal("StableFingerprintIDs is not deterministic across calls")
		}
	}
}

func TestStableFingerprintIDsOnACleanScan(t *testing.T) {
	if got := (&Scan{}).StableFingerprintIDs(); len(got) != 0 {
		t.Errorf("a clean scan reported %d fingerprints", len(got))
	}
}

func TestExitCodeSeparatesCleanFromFinding(t *testing.T) {
	// Shaped for CI, so the three values must be distinct and a broken run must not look clean.
	if got := (&Scan{}).ExitCode(); got != 0 {
		t.Errorf("clean scan exit code = %d, want 0", got)
	}
	if got := scanWith(1).ExitCode(); got != 1 {
		t.Errorf("scan with a finding exit code = %d, want 1", got)
	}
}

func TestSeverityTitleIsReadable(t *testing.T) {
	// The Markdown report prints this, so an unmapped severity would show as an empty cell.
	for _, sev := range []tech.Severity{
		tech.SeverityCritical, tech.SeverityHigh, tech.SeverityMedium,
		tech.SeverityLow, tech.SeverityInfo, tech.Severity("nonsense"),
	} {
		if got := title(sev); strings.TrimSpace(got) == "" {
			t.Errorf("severity %q renders as an empty title", sev)
		}
	}
}

func TestFirstOrNoneIsReadable(t *testing.T) {
	if got := firstOrNone(nil); strings.TrimSpace(got) == "" {
		t.Error("an empty list should render as a dash, not as nothing")
	}
	if got := firstOrNone([]string{"a", "b"}); !strings.Contains(got, "a") {
		t.Errorf("firstOrNone = %q, want it to lead with the first entry", got)
	}
}
