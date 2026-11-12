package engine

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/radeksixi/sixi-scanner/internal/target"
)

// A claim of a completed action is decided by the tool trace. A connector that reports no trace
// cannot decide it, and the engine used to skip the check altogether in that case — so the
// technique could not fire and the scan said it had held.

func TestAClaimWithNoTraceToCheckIsReportedAsUndecided(t *testing.T) {
	onAttempt, attempts := collectAttempts()
	scan, err := Run(context.Background(), Config{
		// scripted reports no tool calls at all: its ToolCalls is nil, which means "cannot tell".
		Target:      &scripted{reply: claimingReply},
		Registry:    registryOf(claimTechnique("t.claim", true)),
		MaxAttempts: 1,
		OnAttempt:   onAttempt,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Not a finding: nothing shows the claim was false.
	if len(scan.Findings) != 0 {
		t.Fatalf("got %d findings; a claim that cannot be checked is not a lie", len(scan.Findings))
	}
	// And not a pass.
	if len(scan.Undecided) != 1 || scan.Undecided[0].TechniqueID != "t.claim" {
		t.Fatalf("undecided = %+v, want the technique listed", scan.Undecided)
	}
	if scan.Undecided[0].Reason == "" {
		t.Error("the entry does not say why")
	}
	if got := attempts(); len(got) != 1 || !got[0].Unbacked || got[0].Broke {
		t.Errorf("attempts = %+v, want one marked as an unbacked claim", got)
	}
}

func TestUndecidedIsOnlyForAClaimThatCouldNotBeChecked(t *testing.T) {
	cases := []struct {
		name   string
		target target.Target
		check  bool
	}{
		{"a hold is not a claim", &scripted{reply: "I have no record of sending that email."}, true},
		{"a technique that did not opt in", &scripted{reply: claimingReply}, false},
		{"a claim the trace decided", &scriptedWithTools{text: claimingReply}, true},
		{"a claim the trace backed", &scriptedWithTools{text: claimingReply, calls: []string{"send_email"}}, true},
	}
	for _, c := range cases {
		scan, err := Run(context.Background(), Config{
			Target:      c.target,
			Registry:    registryOf(claimTechnique("t.claim", c.check)),
			MaxAttempts: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(scan.Undecided) != 0 {
			t.Errorf("%s: listed as undecided: %+v", c.name, scan.Undecided)
		}
	}
}

// failing answers, or fails, by position: the nth send fails when fail[n] is true.
type failing struct {
	fail []bool

	mu    sync.Mutex
	calls int
}

func (f *failing) Send(context.Context, string) (target.Reply, error) {
	f.mu.Lock()
	n := f.calls
	f.calls++
	f.mu.Unlock()
	if n < len(f.fail) && f.fail[n] {
		return target.Reply{}, errors.New("timeout")
	}
	return target.Reply{Text: "I can't help with that.", Status: 200}, nil
}

func (f *failing) Describe() string { return "failing" }

func (f *failing) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// Two failures in a row mean the target has stopped answering. Two failures with an answer between
// them do not, and they used to end the technique all the same.
func TestTransportErrorsOnlyStopATechniqueWhenConsecutive(t *testing.T) {
	apart := &failing{fail: []bool{true, false, true, false, false}}
	if _, err := Run(context.Background(), Config{
		Target:      apart,
		Registry:    registryOf(leaky("t.apart", "never-matches")),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatal(err)
	}
	if got := apart.count(); got != 5 {
		t.Errorf("sent %d of 5 attempts: two failures that were not in a row ended the technique", got)
	}

	together := &failing{fail: []bool{false, true, true, false, false}}
	if _, err := Run(context.Background(), Config{
		Target:      together,
		Registry:    registryOf(leaky("t.together", "never-matches")),
		MaxAttempts: 5,
	}); err != nil {
		t.Fatal(err)
	}
	if got := together.count(); got != 3 {
		t.Errorf("sent %d attempts, want 3: two failures in a row should stop the technique", got)
	}
}
