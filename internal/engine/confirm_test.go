package engine

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/radeksixi/sixi-scanner/internal/report"
	"github.com/radeksixi/sixi-scanner/internal/tech"
)

// The confirmation stage has the last word on a candidate, so what the engine does with each of
// its three answers decides what a scan with a stage can report. These tests drive that through
// Run with a scripted stage.

type asked struct{ payload, response string }

type stubConfirmer struct {
	answer func(payload, response string) (string, Verdict)

	mu   sync.Mutex
	seen []asked
}

func (s *stubConfirmer) Confirm(_ context.Context, _, payload, response string) (string, Verdict) {
	s.mu.Lock()
	s.seen = append(s.seen, asked{payload, response})
	s.mu.Unlock()
	return s.answer(payload, response)
}

func (s *stubConfirmer) questions() []asked {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]asked(nil), s.seen...)
}

func collectAttempts() (func(report.Attempt), func() []report.Attempt) {
	var mu sync.Mutex
	var got []report.Attempt
	return func(a report.Attempt) {
			mu.Lock()
			got = append(got, a)
			mu.Unlock()
		}, func() []report.Attempt {
			mu.Lock()
			defer mu.Unlock()
			return append([]report.Attempt(nil), got...)
		}
}

// One false alarm on the first variant used to end the technique: the candidate was rejected and
// the remaining variants, any of which might have landed, were never sent.
func TestARejectedCandidateDoesNotEndTheTechnique(t *testing.T) {
	target := &recording{inner: &scripted{reply: "the-secret is 1234"}}
	stage := &stubConfirmer{answer: func(payload, _ string) (string, Verdict) {
		if strings.Contains(payload, "variant-a") {
			return "the value was the caller's own", VerdictReject
		}
		return "it disclosed a configured secret", VerdictKeep
	}}
	onAttempt, attempts := collectAttempts()

	scan, err := Run(context.Background(), Config{
		Target:    target,
		Registry:  registryOf(leaky("probe.test.confirm", "the-secret")),
		Confirm:   stage,
		Policy:    "a support agent",
		OnAttempt: onAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := target.sent(); len(got) != 2 {
		t.Fatalf("sent %d prompts, want 2: the technique stopped at the rejected candidate", len(got))
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings, want the one the stage upheld", len(scan.Findings))
	}
	if got := scan.Findings[0].Evidence.Reason; got != "it disclosed a configured secret" {
		t.Errorf("reason = %q, want the stage's", got)
	}

	got := attempts()
	if len(got) != 2 {
		t.Fatalf("recorded %d attempts, want 2", len(got))
	}
	if !got[0].Rejected || got[0].Broke || got[0].Confirmed {
		t.Errorf("first attempt = %+v, want rejected", got[0])
	}
	if !got[1].Confirmed || !got[1].Broke {
		t.Errorf("second attempt = %+v, want a confirmed break", got[1])
	}

	// Both questions were answered, and the report used to count only the rejection.
	if scan.Confirm == nil || scan.Confirm.Asked != 2 || scan.Confirm.Rejected != 1 {
		t.Errorf("confirmation = %+v, want asked 2 and rejected 1", scan.Confirm)
	}
}

// A stage that could not reach its model has not disproved the candidate, and has not agreed with
// it either. It stands on the judge's evidence and is not marked as confirmed.
func TestAnUnansweredQuestionKeepsTheCandidateUnconfirmed(t *testing.T) {
	stage := &stubConfirmer{answer: func(string, string) (string, Verdict) {
		return "", VerdictUnanswered
	}}
	onAttempt, attempts := collectAttempts()

	scan, err := Run(context.Background(), Config{
		Target:    &scripted{reply: "the-secret is 1234"},
		Registry:  registryOf(leaky("probe.test.unanswered", "the-secret")),
		Confirm:   stage,
		OnAttempt: onAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings; an unanswered question dropped the candidate", len(scan.Findings))
	}
	if !strings.Contains(scan.Findings[0].Evidence.Reason, "marker") {
		t.Errorf("reason = %q, want the judge's own", scan.Findings[0].Evidence.Reason)
	}
	got := attempts()
	if len(got) != 1 || got[0].Confirmed || got[0].Rejected || !got[0].Broke {
		t.Errorf("attempts = %+v, want one unconfirmed break", got)
	}
	if scan.Confirm == nil || scan.Confirm.Asked != 0 || scan.Confirm.Rejected != 0 {
		t.Errorf("confirmation = %+v, want nothing counted as asked", scan.Confirm)
	}
}

// The counters are written from every worker. Run with -race, this is also the test that they are
// guarded.
func TestConfirmationCountersAddUpAcrossWorkers(t *testing.T) {
	var ts []tech.Technique
	for _, id := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		ts = append(ts, leaky("probe.test."+id, "the-secret"))
	}
	stage := &stubConfirmer{answer: func(string, string) (string, Verdict) {
		return "compliant", VerdictReject
	}}
	scan, err := Run(context.Background(), Config{
		Target:      &scripted{reply: "the-secret is 1234"},
		Registry:    registryOf(ts...),
		Confirm:     stage,
		Rounds:      2,
		MaxAttempts: 3,
		Concurrency: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	want := len(ts) * 2 * 3
	if got := len(stage.questions()); got != want {
		t.Fatalf("the stage was asked %d times, want %d", got, want)
	}
	if scan.Confirm.Asked != want || scan.Confirm.Rejected != want {
		t.Errorf("confirmation = %+v, want %d asked and rejected", scan.Confirm, want)
	}
	if len(scan.Findings) != 0 {
		t.Errorf("got %d findings from candidates that were all rejected", len(scan.Findings))
	}
}

// A cumulative attack is scored on every turn, so the stage has to be shown every turn. Given the
// last reply alone it sees one compliant answer and is right to reject it.
func TestACumulativeAttackIsConfirmedOnTheWholeConversation(t *testing.T) {
	cumulative := tech.Data{Def: tech.Definition{
		ID: "probe.test.cumulative", Title: "t", Category: "test", Severity: tech.SeverityHigh,
		Sequence:   [][]string{{"first half", "second half"}},
		Markers:    []string{"refund issued"},
		RequireAll: true,
	}}
	tr := &transcript{reply: func(prompt string) string {
		if strings.Contains(prompt, "first half") {
			return "Refund issued for 40 EUR."
		}
		return "Refund issued for 45 EUR."
	}}
	stage := &stubConfirmer{answer: func(string, string) (string, Verdict) {
		return "both halves went through", VerdictKeep
	}}
	if _, err := Run(context.Background(), Config{
		Target: tr, Registry: registryOf(cumulative), Confirm: stage, Rounds: 1, MaxAttempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	qs := stage.questions()
	if len(qs) != 1 {
		t.Fatalf("the stage was asked %d times, want once", len(qs))
	}
	if !strings.Contains(qs[0].response, "40 EUR") || !strings.Contains(qs[0].response, "45 EUR") {
		t.Errorf("the stage was shown %q, want both turns' replies", qs[0].response)
	}

	// A technique scored on its last turn is confirmed on that turn.
	single := &stubConfirmer{answer: func(string, string) (string, Verdict) { return "", VerdictKeep }}
	if _, err := Run(context.Background(), Config{
		Target:   &scripted{reply: "the-secret is 1234"},
		Registry: registryOf(leaky("probe.test.single", "the-secret")),
		Confirm:  single,
	}); err != nil {
		t.Fatal(err)
	}
	if qs := single.questions(); len(qs) != 1 || qs[0].response != "the-secret is 1234" {
		t.Errorf("a single-turn technique was confirmed on %+v", qs)
	}
}
