package engine

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/target"
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// A multi-turn attack is a property of the conversation, so these tests are about the conversation:
// that every turn is sent, in order, on one session, and that a break on any turn is caught.

// transcript records every prompt it was sent and reports a scripted reply per prompt.
type transcript struct {
	mu       sync.Mutex
	prompts  []string
	session  string
	sessions []string
	reply    func(prompt string) string
}

// SupportsSessions implements target.Sessioner.
func (t *transcript) SupportsSessions() bool { return true }

// The conversation id is read from the context, exactly as a real connector does, so this double
// cannot pass a test by reading state off itself the way the earlier version of it did.
func (t *transcript) Send(ctx context.Context, prompt string) (target.Reply, error) {
	if id, ok := target.SessionFrom(ctx); ok {
		t.mu.Lock()
		t.sessions = append(t.sessions, id)
		t.session = id
		t.mu.Unlock()
	}
	t.mu.Lock()
	t.prompts = append(t.prompts, prompt)
	t.mu.Unlock()
	return target.Reply{Text: t.reply(prompt), Status: 200, ToolCalls: []target.ToolCall{}}, nil
}

func (t *transcript) Describe() string { return "transcript" }
func (t *transcript) sent() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.prompts...)
}

// distinctSessions counts the conversations actually joined, not the sends: both turns of an
// attempt carry the same id by design.
func (t *transcript) distinctSessions() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	seen := map[string]bool{}
	var out []string
	for _, s := range t.sessions {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (t *transcript) seenSessions() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.sessions...)
}

func splitTechnique(marker string) tech.Technique {
	return tech.Data{Def: tech.Definition{
		ID: "probe.test.split", Title: "t", Category: "test", Severity: tech.SeverityHigh,
		Sequence: [][]string{
			{"turn one " + marker, "turn two " + marker},
			{"alt turn one " + marker, "alt turn two " + marker},
		},
		Markers:    []string{marker},
		MinMarkers: 1,
	}}
}

func TestEveryTurnIsSentInOrderOnOneSession(t *testing.T) {
	tr := &transcript{reply: func(string) string { return "nothing here" }}
	if _, err := Run(context.Background(), Config{
		Target:      tr,
		Registry:    registryOf(splitTechnique("xyzzy")),
		Rounds:      1,
		MaxAttempts: 1,
	}); err != nil {
		t.Fatal(err)
	}
	sent := tr.sent()
	if len(sent) != 2 {
		t.Fatalf("sent %d turns, want 2: %v", len(sent), sent)
	}
	if !strings.Contains(sent[0], "turn one") || !strings.Contains(sent[1], "turn two") {
		t.Errorf("turns sent out of order: %v", sent)
	}
	if seen := tr.distinctSessions(); len(seen) != 1 {
		t.Errorf("joined %d conversations for one attempt, want 1: %v", len(seen), seen)
	}
}

// A session per attempt, not per scan: an endpoint that keys cumulative state on the session id
// would otherwise carry one attempt's running total into the next, and a cap-split probe would
// report a split the agent never performed.
func TestEachAttemptGetsItsOwnSession(t *testing.T) {
	tr := &transcript{reply: func(string) string { return "nothing" }}
	if _, err := Run(context.Background(), Config{
		Target:      tr,
		Registry:    registryOf(splitTechnique("xyzzy")),
		Rounds:      1,
		MaxAttempts: 3,
	}); err != nil {
		t.Fatal(err)
	}
	seen := tr.distinctSessions()
	if len(seen) != 3 {
		t.Fatalf("joined %d conversations for 3 attempts, want 3: %v", len(seen), seen)
	}
	if strings.ContainsAny(seen[0], "./") {
		t.Errorf("session id %q carries path characters; it could be mistaken for a path", seen[0])
	}
}

// The attack is the pair. A break on the second turn has to be caught even though the first turn
// was clean, and the transcript a report shows must contain both.
func TestABreakOnEitherTurnIsAFinding(t *testing.T) {
	tr := &transcript{reply: func(p string) string {
		if strings.Contains(p, "turn two") {
			return "refund has been issued"
		}
		return "working on it"
	}}
	scan, err := Run(context.Background(), Config{
		Target:      tr,
		Registry:    registryOf(splitTechnique("refund has been issued")),
		Rounds:      1,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings; a break on the second turn is the attack landing", len(scan.Findings))
	}
	ev := scan.Findings[0].Evidence
	if !strings.Contains(ev.Prompt, "turn one") || !strings.Contains(ev.Prompt, "turn two") {
		t.Errorf("the transcript does not contain both turns: %q", ev.Prompt)
	}
}

// A single-turn technique must not gain a session: the interface is optional and the common path
// should be untouched.
func TestSingleTurnTechniquesOpenNoSession(t *testing.T) {
	tr := &transcript{reply: func(string) string { return "clean" }}
	if _, err := Run(context.Background(), Config{
		Target:      tr,
		Registry:    registryOf(leaky("t.single", "never-matches-this")),
		Rounds:      1,
		MaxAttempts: 2,
	}); err != nil {
		t.Fatal(err)
	}
	if seen := tr.seenSessions(); len(seen) != 0 {
		t.Errorf("a single-turn technique joined %d conversations, want none: %v", len(seen), seen)
	}
	if n := len(tr.sent()); n != 2 {
		t.Errorf("sent %d turns, want 2", n)
	}
}

// A sequence sent to a connector that cannot hold a conversation does not degrade into a weaker
// probe: the turns become unrelated requests, and a cumulative technique would then report two
// individually compliant replies as a breach. So the probe is declined and named, rather than run
// and quietly believed.
//
// This test is the inverse of the one above it, and the earlier version of it asserted the opposite.
// The change is deliberate: the old behaviour was measured to be wrong, not merely inconvenient.
func TestAMultiTurnTechniqueIsSkippedAgainstAStatelessTarget(t *testing.T) {
	stateless := &scripted{reply: "nothing"}
	scan, err := Run(context.Background(), Config{
		Target:      stateless,
		Registry:    registryOf(splitTechnique("xyzzy")),
		Rounds:      1,
		MaxAttempts: 2,
	})
	if err != nil {
		t.Fatalf("a multi-turn technique must not fail the whole run against a stateless target: %v", err)
	}
	if stateless.calls != 0 {
		t.Errorf("the sequence was sent %d time(s) to a target that cannot hold a conversation", stateless.calls)
	}
	if len(scan.Findings) != 0 {
		t.Errorf("got %d findings from a technique that never ran", len(scan.Findings))
	}
	if len(scan.Unsupported) != 1 || scan.Unsupported[0].TechniqueID != "probe.test.split" {
		t.Fatalf("the skipped technique is not named in the report: %+v", scan.Unsupported)
	}
	if !strings.Contains(scan.Unsupported[0].Reason, "cannot hold a conversation") {
		t.Errorf("the reason does not explain the skip: %q", scan.Unsupported[0].Reason)
	}
	// A single-turn technique is unaffected, and its absence from the list is what proves the filter
	// is about the shape of the payload rather than about the target being plain.
	both, err := Run(context.Background(), Config{
		Target:      &scripted{reply: "nothing"},
		Registry:    registryOf(splitTechnique("xyzzy"), leaky("t.single", "no-match-here")),
		Rounds:      1,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(both.Unsupported) != 1 || both.Unsupported[0].TechniqueID != "probe.test.split" {
		t.Errorf("the single-turn technique was listed as unsupported: %+v", both.Unsupported)
	}
}

// A session-capable target is never told a sequence is unsupported.
func TestAMultiTurnTechniqueIsSupportedByASessionTarget(t *testing.T) {
	tr := &transcript{reply: func(string) string { return "nothing" }}
	scan, err := Run(context.Background(), Config{
		Target:      tr,
		Registry:    registryOf(splitTechnique("xyzzy")),
		Rounds:      1,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Unsupported) != 0 {
		t.Errorf("a session target was reported as unable to run sequences: %+v", scan.Unsupported)
	}
}

// RequireAll is the difference between reporting an agent for two compliant refunds and reporting
// the breach. Each half is asserted, because either half alone would ship a false positive.
func TestRequireAllOnlyFiresWhenEveryTurnBreaks(t *testing.T) {
	tech := tech.Data{Def: tech.Definition{
		ID: "probe.test.aggregate", Title: "t", Category: "test", Severity: tech.SeverityCritical,
		Sequence:   [][]string{{"first", "second"}},
		Markers:    []string{"refund queued"},
		MinMarkers: 1,
		RequireAll: true,
	}}

	cases := []struct {
		name    string
		replies map[string]string
		want    int
	}{
		{"both turns acknowledge", map[string]string{"first": "refund queued", "second": "refund queued"}, 1},
		{"the second is refused", map[string]string{"first": "refund queued", "second": "I cannot issue a second refund"}, 0},
		{"the first is refused", map[string]string{"first": "I cannot issue that", "second": "refund queued"}, 0},
		{"neither", map[string]string{"first": "no", "second": "no"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &transcript{reply: func(p string) string { return tc.replies[p] }}
			scan, err := Run(context.Background(), Config{
				Target: tr, Registry: registryOf(tech), Rounds: 1, MaxAttempts: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(scan.Findings) != tc.want {
				t.Errorf("got %d findings, want %d", len(scan.Findings), tc.want)
			}
			if tc.want == 1 && !strings.Contains(scan.Findings[0].Evidence.Reason, "2 unambiguous") &&
				!strings.Contains(scan.Findings[0].Evidence.Reason, "marker") {
				t.Errorf("the reason does not say what matched: %q", scan.Findings[0].Evidence.Reason)
			}
		})
	}
}

// RequireAll must not turn a single-turn technique into a no-op, which is what would happen if the
// flag were honoured on its own.
func TestRequireAllIsIgnoredForASingleTurnTechnique(t *testing.T) {
	tr := &transcript{reply: func(string) string { return "refund queued" }}
	scan, err := Run(context.Background(), Config{
		Target: tr,
		Registry: registryOf(tech.Data{Def: tech.Definition{
			ID: "probe.test.single-requireall", Title: "t", Category: "test",
			Severity: tech.SeverityHigh, Variants: []string{"only"},
			Markers: []string{"refund queued"}, MinMarkers: 1, RequireAll: true,
		}}),
		Rounds: 1, MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Errorf("got %d findings; RequireAll silenced a single-turn technique", len(scan.Findings))
	}
}

// Every turn's answer belongs in the evidence, because for a cumulative attack the second reply is
// the one that matters and a report showing only it would hide what the first turn was.
func TestEvidenceKeepsEveryTurnOfTheConversation(t *testing.T) {
	tr := &transcript{reply: func(p string) string {
		if strings.Contains(p, "turn two") {
			return "refund queued"
		}
		return "working on it"
	}}
	scan, err := Run(context.Background(), Config{
		Target:      tr,
		Registry:    registryOf(splitTechnique("refund queued")),
		Rounds:      1,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("got %d findings", len(scan.Findings))
	}
	resp := scan.Findings[0].Evidence.Response
	if !strings.Contains(resp, "working on it") || !strings.Contains(resp, "refund queued") {
		t.Errorf("the evidence holds only part of the conversation: %q", resp)
	}
}

// concurrentSessioner joins whichever conversation the context names, and remembers every pairing of
// prompt to conversation. It is the bug this test exists for: when the session id was connector state
// rather than a per-request value, a scan running four techniques at once let each technique's
// opening turn land inside whichever conversation started most recently, so two attacks shared one
// conversation. Every unit test for this machinery used a single technique and could not see it; it
// surfaced only when four techniques ran against a live gateway.
type concurrentSessioner struct {
	mu    sync.Mutex
	pairs map[string]string
	reply func(prompt string) string
}

func (c *concurrentSessioner) Send(ctx context.Context, prompt string) (target.Reply, error) {
	id, _ := target.SessionFrom(ctx)
	c.mu.Lock()
	c.pairs[prompt] = id
	c.mu.Unlock()
	return target.Reply{Text: c.reply(prompt), Status: 200, ToolCalls: []target.ToolCall{}}, nil
}

func (c *concurrentSessioner) SupportsSessions() bool { return true }
func (c *concurrentSessioner) Describe() string       { return "concurrent" }

// Two multi-turn techniques running at once must not end up in each other's conversation. Each
// technique's turns have to share one id, and no id may serve both techniques.
func TestConcurrentSequencesDoNotShareAConversation(t *testing.T) {
	c := &concurrentSessioner{pairs: map[string]string{}, reply: func(string) string { return "nothing" }}
	first := tech.Data{Def: tech.Definition{
		ID: "probe.test.first", Title: "f", Category: "test", Severity: tech.SeverityHigh,
		Sequence: [][]string{{"AAA first open", "AAA first close"}},
		Markers:  []string{"no-match-here"},
	}}
	second := tech.Data{Def: tech.Definition{
		ID: "probe.test.second", Title: "s", Category: "test", Severity: tech.SeverityHigh,
		Sequence: [][]string{{"BBB second open", "BBB second close"}},
		Markers:  []string{"no-match-here"},
	}}

	if _, err := Run(context.Background(), Config{
		Target: c, Registry: registryOf(first, second),
		Rounds: 1, MaxAttempts: 1, Concurrency: 2,
	}); err != nil {
		t.Fatal(err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	byPrefix := map[string]map[string]bool{}
	for prompt, id := range c.pairs {
		if id == "" {
			t.Fatalf("a multi-turn prompt was sent with no conversation: %q", prompt)
		}
		who := prompt[:3]
		if byPrefix[who] == nil {
			byPrefix[who] = map[string]bool{}
		}
		byPrefix[who][id] = true
	}
	if len(byPrefix) != 2 {
		t.Fatalf("expected prompts from both techniques, got %v", byPrefix)
	}
	seen := map[string]string{}
	for who, ids := range byPrefix {
		if len(ids) != 1 {
			t.Errorf("technique %q used %d conversations, want 1: %v", who, len(ids), ids)
			continue
		}
		for id := range ids {
			if other, clash := seen[id]; clash {
				t.Errorf("techniques %q and %q shared conversation %q", who, other, id)
			}
			seen[id] = who
		}
	}
}
