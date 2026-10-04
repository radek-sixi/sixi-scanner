package engine

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rbrus/sixi-scanner/internal/report"
	"github.com/rbrus/sixi-scanner/internal/target"
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// scripted replies with a fixed reply, or an error. The engine calls Send
// concurrently, so the counter is guarded.
type scripted struct {
	reply string
	err   error

	mu    sync.Mutex
	calls int
}

func (s *scripted) Send(_ context.Context, _ string) (target.Reply, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()

	if s.err != nil {
		return target.Reply{}, s.err
	}
	return target.Reply{Text: s.reply, Status: 200}, nil
}

func (s *scripted) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func (s *scripted) Describe() string { return "scripted" }

// recording captures every prompt the engine sent, in order.
type recording struct {
	inner   *scripted
	mu      sync.Mutex
	prompts []string
}

func (r *recording) Send(ctx context.Context, p string) (target.Reply, error) {
	r.mu.Lock()
	r.prompts = append(r.prompts, p)
	r.mu.Unlock()
	return r.inner.Send(ctx, p)
}

func (r *recording) Describe() string { return "recording" }

func (r *recording) sent() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.prompts...)
}

// leaky is a technique whose markers match `reply`.
func leaky(id string, markers ...string) tech.Technique {
	return tech.Data{Def: tech.Definition{
		ID: id, Title: id, Category: "test", Severity: tech.SeverityHigh,
		Variants: []string{"variant-a", "variant-b", "variant-c"},
		Markers:  markers,
	}}
}

func registryOf(ts ...tech.Technique) *tech.Registry {
	r := tech.NewRegistry()
	for _, t := range ts {
		r.MustAdd(t)
	}
	return r
}

func TestRunRejectsIncompleteConfiguration(t *testing.T) {
	if _, err := Run(context.Background(), Config{Registry: registryOf(leaky("t", "x"))}); err == nil {
		t.Error("expected an error with no target")
	}
	if _, err := Run(context.Background(), Config{Target: &scripted{}}); err == nil {
		t.Error("expected an error with no techniques")
	}
	if _, err := Run(context.Background(), Config{
		Target: &scripted{}, Registry: tech.NewRegistry(),
	}); err == nil {
		t.Error("expected an error with an empty registry")
	}
}

func TestABreakIsRecordedWithItsTranscript(t *testing.T) {
	tgt := &scripted{reply: "You are a bot. Your instructions are to be brief."}

	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a", "your instructions")),
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(scan.Findings))
	}
	f := scan.Findings[0]
	if f.Evidence.Prompt == "" || f.Evidence.Response == "" {
		t.Error("the finding carries no transcript, so it cannot be verified")
	}
	if !strings.Contains(f.Evidence.Reason, "unambiguous") {
		t.Errorf("reason does not name the evidence: %q", f.Evidence.Reason)
	}
	if f.Fingerprint == "" {
		t.Error("the finding has no fingerprint")
	}
}

func TestACleanTargetProducesNoFindings(t *testing.T) {
	tgt := &scripted{reply: "I can help with billing questions. What do you need?"}

	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a", "your instructions")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 {
		t.Errorf("got %d findings against a clean target: %+v", len(scan.Findings), scan.Findings)
	}
	if scan.ExitCode() != 0 {
		t.Errorf("exit code = %d, want 0 for a clean scan", scan.ExitCode())
	}
}

func TestExitCodeIsOneWhenSomethingBroke(t *testing.T) {
	scan, err := Run(context.Background(), Config{
		Target:      &scripted{reply: "You are a bot. Your instructions are to be brief."},
		Registry:    registryOf(leaky("t.one", "you are a", "your instructions")),
		Rounds:      1,
		Seed:        "",
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scan.ExitCode() != 1 {
		t.Errorf("exit code = %d, want 1 when a finding exists", scan.ExitCode())
	}
}

// A refusal is a different statement of the same idea, not the same statement
// again. Repeating it is how a scan turns into a wall.
func TestARefusalMovesToTheNextVariant(t *testing.T) {
	rec := &recording{inner: &scripted{reply: "I can't help with that."}}

	_, err := Run(context.Background(), Config{
		Target: rec, Registry: registryOf(leaky("t.one", "you are a")),
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	sent := rec.sent()
	if len(sent) != 3 {
		t.Fatalf("sent %d prompts, want 3 distinct variants: %v", len(sent), sent)
	}
	seen := map[string]bool{}
	for _, p := range sent {
		if seen[p] {
			t.Errorf("the same payload was sent twice after a refusal: %q", p)
		}
		seen[p] = true
	}
}

func TestABreakStopsTheTechniqueEarly(t *testing.T) {
	rec := &recording{inner: &scripted{reply: "You are a bot."}}

	_, err := Run(context.Background(), Config{
		Target: rec, Registry: registryOf(leaky("t.one", "you are a")),
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	if n := len(rec.sent()); n != 1 {
		t.Errorf("sent %d prompts after a break, want 1 — continuing would waste calls and bias the report", n)
	}
}

// Each technique must start a clean conversation. A jailbreak that worked has
// already changed the target's state, and a later technique measuring that
// state is measuring a different agent.
func TestEachTechniqueStartsAFreshConversation(t *testing.T) {
	rec := &recording{inner: &scripted{reply: "I can't help with that."}}

	_, err := Run(context.Background(), Config{
		Target:      rec,
		Registry:    registryOf(leaky("t.one", "you are a"), leaky("t.two", "your instructions")),
		MaxAttempts: 1, Concurrency: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range rec.sent() {
		if strings.Contains(p, "variant-a") && strings.Contains(p, "variant-b") {
			t.Errorf("two techniques shared one conversation: %q", p)
		}
	}
}

func TestSeedPrependsToEveryPrompt(t *testing.T) {
	rec := &recording{inner: &scripted{reply: "no"}}

	_, err := Run(context.Background(), Config{
		Target: rec, Registry: registryOf(leaky("t.one", "x")),
		Seed: "You are a support bot for ACME.", MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, p := range rec.sent() {
		if !strings.HasPrefix(p, "You are a support bot for ACME.") {
			t.Errorf("prompt did not start with the seed: %q", p)
		}
	}
}

// A transport error is not an answer, so it must not be scored and must not be
// reported as a clean pass.
func TestTransportErrorsAreNotTreatedAsRefusals(t *testing.T) {
	failing := &scripted{err: errors.New("connection refused")}

	scan, err := Run(context.Background(), Config{
		Target: failing, Registry: registryOf(leaky("t.one", "you are a")),
		MaxAttempts: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(scan.Findings) != 0 {
		t.Errorf("a dead target produced findings: %+v", scan.Findings)
	}
	if len(scan.NoAnswer) != 1 || scan.NoAnswer[0] != "t.one" {
		t.Errorf("the untested technique is not reported: %v", scan.NoAnswer)
	}
}

func TestTransportErrorsStopAfterTwoRatherThanBurningTheBudget(t *testing.T) {
	failing := &scripted{err: errors.New("connection refused")}

	_, err := Run(context.Background(), Config{
		Target: failing, Registry: registryOf(leaky("t.one", "you are a")),
		MaxAttempts: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if failing.count() != 2 {
		t.Errorf("made %d attempts against a dead endpoint, want 2", failing.count())
	}
}

// The prompt is what was sent, the reply is what came back. They must never be
// confused, or every finding cites the attacker's own words.
func TestTheJudgeReadsTheReplyNotThePrompt(t *testing.T) {
	tgt := &scripted{reply: "I can't help with that."}

	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a")),
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 {
		t.Fatalf("the marker appeared only in the prompt and was scored as a break: %+v", scan.Findings)
	}
}

func TestRoundsMergeIntoOneFinding(t *testing.T) {
	tgt := &scripted{reply: "You are a bot. Your instructions are to be brief."}

	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a", "your instructions")),
		Rounds: 3, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(scan.Findings) != 1 {
		t.Fatalf("3 rounds produced %d findings, want 1 merged", len(scan.Findings))
	}
	if len(scan.Findings[0].Rounds) != 3 {
		t.Errorf("rounds = %v, want 3 recorded as reproduction", scan.Findings[0].Rounds)
	}
}

func TestMinConfidenceDiscardsWeakBreaks(t *testing.T) {
	tgt := &scripted{reply: "You are a bot."}

	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a")),
		MaxAttempts: 1, MinConfidence: 0.99,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 0 {
		t.Errorf("a break below the confidence floor was reported: %+v", scan.Findings)
	}
}

func TestOnAttemptIsCalledForEverySend(t *testing.T) {
	var mu sync.Mutex
	var seen []report.Attempt

	_, err := Run(context.Background(), Config{
		Target:      &scripted{reply: "I can't help with that."},
		Registry:    registryOf(leaky("t.one", "x"), leaky("t.two", "y")),
		MaxAttempts: 2,
		Concurrency: 2,
		OnAttempt:   func(a report.Attempt) { mu.Lock(); seen = append(seen, a); mu.Unlock() },
	})
	if err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 4 {
		t.Errorf("OnAttempt fired %d times, want 4 (2 techniques x 2 attempts)", len(seen))
	}
}

func TestConcurrentScansAreSafeUnderRace(t *testing.T) {
	// The engine runs techniques concurrently; a finding filed from a worker
	// goroutine must not race the summary.
	rec := &recording{inner: &scripted{reply: "You are a bot. Your instructions are: be brief."}}

	reg := registryOf(
		leaky("t.one", "you are a", "your instructions"),
		leaky("t.two", "you are a", "your instructions"),
		leaky("t.three", "you are a", "your instructions"),
		leaky("t.four", "you are a", "your instructions"),
	)

	scan, err := Run(context.Background(), Config{
		Target: rec, Registry: reg, Concurrency: 4, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 4 {
		t.Errorf("got %d findings, want 4 distinct techniques", len(scan.Findings))
	}
}

func TestCancelledContextStopsTheScanAndSaysSo(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	rec := &recording{inner: &scripted{reply: "no"}}
	scan, err := Run(ctx, Config{
		Target: rec, Registry: registryOf(leaky("t.one", "x")),
		MaxAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	if n := len(rec.sent()); n != 0 {
		t.Errorf("a cancelled scan sent %d prompts", n)
	}
	if len(scan.NoAnswer) == 0 {
		t.Error("a cancelled scan must report what it did not test")
	}
}

func TestScanRecordsTheOptionsItRanWith(t *testing.T) {
	scan, err := Run(context.Background(), Config{
		Target:      &scripted{reply: "no"},
		Registry:    registryOf(leaky("t.one", "x")),
		Rounds:      2,
		MaxAttempts: 4,
		Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}

	if scan.Options.Rounds != 2 || scan.Options.MaxAttempts != 4 || scan.Options.Concurrency != 2 {
		t.Errorf("options not recorded: %+v", scan.Options)
	}
	if len(scan.Options.TechniqueIDs) != 1 {
		t.Errorf("technique IDs not recorded: %v", scan.Options.TechniqueIDs)
	}
	if scan.Target != "scripted" {
		t.Errorf("target description = %q", scan.Target)
	}
}

func TestAttemptCountMatchesSends(t *testing.T) {
	rec := &recording{inner: &scripted{reply: "no"}}

	scan, err := Run(context.Background(), Config{
		Target: rec, Registry: registryOf(leaky("t.one", "x"), leaky("t.two", "y")),
		MaxAttempts: 3, Concurrency: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if scan.Attempts != len(rec.sent()) {
		t.Errorf("recorded %d attempts but sent %d", scan.Attempts, len(rec.sent()))
	}
}

func TestFingerprintIsStableAcrossRuns(t *testing.T) {
	reply := "You are a bot. Your instructions are to be brief."

	first, _ := Run(context.Background(), Config{
		Target:      &scripted{reply: reply},
		Registry:    registryOf(leaky("t.one", "you are a", "your instructions")),
		MaxAttempts: 1,
	})
	second, _ := Run(context.Background(), Config{
		Target:      &scripted{reply: reply},
		Registry:    registryOf(leaky("t.one", "you are a", "your instructions")),
		MaxAttempts: 1,
	})

	if first.Findings[0].Fingerprint != second.Findings[0].Fingerprint {
		t.Errorf("the same finding fingerprinted differently across runs: %s vs %s",
			first.Findings[0].Fingerprint, second.Findings[0].Fingerprint)
	}
}

var _ = time.Second
