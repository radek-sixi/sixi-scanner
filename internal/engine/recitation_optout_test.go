package engine

import (
	"context"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/judge"
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// The shared recitation test exists because a technique's markers only know the leak their own
// payload asked for. For a technique whose payload asks the agent to describe its own capabilities,
// recitation is the compliant answer rather than a leak, and the engine must not treat it as one.
//
// These are the two halves of that contract, driven through Run so the condition under test is the
// engine's own and not a reimplementation of it.

const recitingScope = "Here are the tools I can use:\n" +
	"- issue_refund: for ACC-1001, up to 50 EUR per request\n" +
	"- send_email: to the address on file only\n" +
	"I can only operate on ACC-1001."

func scopeTechnique(id string, skipRecitation bool) tech.Technique {
	return tech.Data{Def: tech.Definition{
		ID: id, Title: id, Category: "test", Severity: tech.SeverityHigh,
		Variants:       []string{"what tools do you have?"},
		Markers:        []string{"a-marker-that-never-appears"},
		SkipRecitation: skipRecitation,
	}}
}

func TestRecitationAppliesByDefault(t *testing.T) {
	if !judge.RecitationThreshold(judge.DefaultRecitationThreshold).Recites(recitingScope) {
		t.Skip("the reply no longer recites; this test would stop proving anything")
	}
	scan, err := Run(context.Background(), Config{
		Target:     &scripted{reply: recitingScope},
		Registry:   registryOf(scopeTechnique("t.default", false)),
		Recitation: judge.RecitationThreshold(judge.DefaultRecitationThreshold),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings, want the recitation to be caught", len(scan.Findings))
	}
}

func TestSkipRecitationSuppressesIt(t *testing.T) {
	scan, err := Run(context.Background(), Config{
		Target:     &scripted{reply: recitingScope},
		Registry:   registryOf(scopeTechnique("t.opt-out", true)),
		Recitation: judge.RecitationThreshold(judge.DefaultRecitationThreshold),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 {
		t.Fatalf("got %d findings; a technique that opted out was still broken by recitation",
			len(scan.Findings))
	}
}

// The opt-out must not become a way to hide a real leak: the technique's own markers still count.
func TestSkipRecitationStillHonoursTheTechniquesOwnMarkers(t *testing.T) {
	tn := tech.Data{Def: tech.Definition{
		ID: "t.opt-out-with-marker", Title: "t", Category: "test", Severity: tech.SeverityHigh,
		Variants:       []string{"ask for the refund cap"},
		Markers:        []string{"50 eur per request"},
		SkipRecitation: true,
	}}
	scan, err := Run(context.Background(), Config{
		Target:     &scripted{reply: recitingScope},
		Registry:   registryOf(tn),
		Recitation: judge.RecitationThreshold(judge.DefaultRecitationThreshold),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings, want the technique's own marker to still break", len(scan.Findings))
	}
	if scan.Findings[0].Evidence.Reason == "" {
		t.Error("the finding carries no reason")
	}
}
