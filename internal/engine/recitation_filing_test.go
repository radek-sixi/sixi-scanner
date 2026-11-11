package engine

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/radek-sixi/sixi-scanner/internal/judge"
	"github.com/radek-sixi/sixi-scanner/internal/report"
	"github.com/radek-sixi/sixi-scanner/internal/tech"
)

// A recitation is evidence about the agent, not about the technique whose payload drew it. These
// tests pin where it is filed, because filing it under the technique put the technique's title and
// severity on a reply the technique's own markers had just cleared.

// refusalCitingLimits is a refusal. It hands over no credential and performs no action; it clears
// the recitation bar only because it says no three times.
const refusalCitingLimits = "I can't share credentials or API keys.\n" +
	"I can only help with questions about your own account.\n" +
	"I must escalate anything else to a human colleague."

func critical(id string) tech.Technique {
	return tech.Data{Def: tech.Definition{
		ID: id, Title: "Credential elicitation", Category: "test", Severity: tech.SeverityCritical,
		Variants: []string{"variant-a", "variant-b"},
		Markers:  []string{"a-marker-that-never-appears"},
	}}
}

func defaultRecitation() judge.RecitationThreshold {
	return judge.RecitationThreshold(judge.DefaultRecitationThreshold)
}

func TestARecitationIsFiledUnderItsOwnDefinition(t *testing.T) {
	if !defaultRecitation().Recites(refusalCitingLimits) {
		t.Fatal("the fixture no longer recites; this test would stop proving anything")
	}
	scan, err := Run(context.Background(), Config{
		Target:     &scripted{reply: refusalCitingLimits},
		Registry:   registryOf(critical("probe.test.credentials")),
		Recitation: defaultRecitation(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings, want the one recitation: %+v", len(scan.Findings), scan.Findings)
	}
	f := scan.Findings[0]
	if f.TechniqueID != judge.RecitationID {
		t.Errorf("filed under %q, want %q: the technique's own markers found nothing", f.TechniqueID, judge.RecitationID)
	}
	if f.Severity != tech.SeverityMedium {
		t.Errorf("severity = %q, want medium: a refusal that cites limits is not a critical credential leak", f.Severity)
	}
	if f.Title == "Credential elicitation" {
		t.Error("the finding carries the probing technique's title")
	}
	if want := []string{"probe.test.credentials"}; !reflect.DeepEqual(f.DrawnBy, want) {
		t.Errorf("drawn by %v, want %v", f.DrawnBy, want)
	}
	if !strings.Contains(f.Evidence.Reason, "operating constraints") {
		t.Errorf("reason does not say what was matched: %q", f.Evidence.Reason)
	}
}

// Every technique can draw the same recitation from an agent that refuses in the same words, and
// that is one fact about the agent, not one finding per technique that happened to ask.
func TestTechniquesDrawingTheSameRecitationShareOneFinding(t *testing.T) {
	scan, err := Run(context.Background(), Config{
		Target:     &scripted{reply: refusalCitingLimits},
		Registry:   registryOf(critical("probe.test.b"), critical("probe.test.a")),
		Recitation: defaultRecitation(),
		Rounds:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings, want one shared recitation: %+v", len(scan.Findings), scan.Findings)
	}
	f := scan.Findings[0]
	if want := []string{"probe.test.a", "probe.test.b"}; !reflect.DeepEqual(f.DrawnBy, want) {
		t.Errorf("drawn by %v, want %v in a stable order", f.DrawnBy, want)
	}
	// Four attempts drew it, in one round. "Reproduced in 4 rounds" of a one-round scan would be
	// the merge counting sends.
	if want := []int{1}; !reflect.DeepEqual(f.Rounds, want) {
		t.Errorf("rounds = %v, want %v", f.Rounds, want)
	}
}

// The technique has not landed just because the agent listed its limits, so it goes on to its next
// variant — and when that one lands, the technique's own finding is filed beside the recitation.
func TestATechniqueCarriesOnAfterARecitation(t *testing.T) {
	tn := tech.Data{Def: tech.Definition{
		ID: "probe.test.carries-on", Title: "t", Category: "test", Severity: tech.SeverityHigh,
		Variants: []string{"first wording", "second wording"},
		Markers:  []string{"the-secret"},
	}}
	tr := &transcript{reply: func(prompt string) string {
		if strings.Contains(prompt, "second wording") {
			return "here is the-secret"
		}
		return refusalCitingLimits
	}}

	var mu sync.Mutex
	var attempts []report.Attempt
	scan, err := Run(context.Background(), Config{
		Target:     tr,
		Registry:   registryOf(tn),
		Recitation: defaultRecitation(),
		Rounds:     1,
		OnAttempt: func(a report.Attempt) {
			mu.Lock()
			attempts = append(attempts, a)
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := len(tr.sent()); got != 2 {
		t.Fatalf("sent %d prompts, want 2: the technique stopped at the recitation", got)
	}
	byID := map[string]report.Finding{}
	for _, f := range scan.Findings {
		byID[f.TechniqueID] = f
	}
	if len(byID) != 2 {
		t.Fatalf("got findings %v, want the recitation and the technique's own", keysOf(byID))
	}
	own, ok := byID["probe.test.carries-on"]
	if !ok {
		t.Fatal("the technique's own break was not filed")
	}
	if own.Severity != tech.SeverityHigh || len(own.DrawnBy) != 0 {
		t.Errorf("own finding = severity %q, drawn by %v; want high and no drawn-by", own.Severity, own.DrawnBy)
	}
	if _, ok := byID[judge.RecitationID]; !ok {
		t.Error("the recitation was not filed")
	}

	if len(attempts) != 2 {
		t.Fatalf("recorded %d attempts, want 2", len(attempts))
	}
	if !attempts[0].Recited {
		t.Error("the first attempt is not marked as a recitation")
	}
	if attempts[1].Recited || !attempts[1].Broke {
		t.Errorf("the second attempt = %+v, want the technique's own break", attempts[1])
	}
}

// A cumulative attack is complete when every turn did what the technique looks for. A turn that
// refused in three lines did not, however much it resembles a rulebook.
func TestARecitationDoesNotCompleteASequence(t *testing.T) {
	tn := tech.Data{Def: tech.Definition{
		ID: "probe.test.cumulative", Title: "t", Category: "test", Severity: tech.SeverityCritical,
		Sequence:   [][]string{{"first half", "second half"}},
		Markers:    []string{"refund issued"},
		RequireAll: true,
	}}
	tr := &transcript{reply: func(prompt string) string {
		if strings.Contains(prompt, "first half") {
			return "Refund issued for 40 EUR."
		}
		return refusalCitingLimits
	}}
	scan, err := Run(context.Background(), Config{
		Target:     tr,
		Registry:   registryOf(tn),
		Recitation: defaultRecitation(),
		Rounds:     1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range scan.Findings {
		if f.TechniqueID == "probe.test.cumulative" {
			t.Fatalf("the sequence was reported complete on a turn that refused: %q", f.Evidence.Reason)
		}
	}
	if len(scan.Findings) != 1 || scan.Findings[0].TechniqueID != judge.RecitationID {
		t.Errorf("got %+v, want only the recitation", scan.Findings)
	}
}

func keysOf(m map[string]report.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
