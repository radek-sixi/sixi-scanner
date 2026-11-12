package engine

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/radeksixi/sixi-scanner/internal/target"
)

// statusOnly answers every prompt with one HTTP status and one body, the way a connector hands back
// a response it could not find a reply in.
type statusOnly struct {
	status int
	text   string

	mu    sync.Mutex
	calls int
}

func (s *statusOnly) Send(_ context.Context, _ string) (target.Reply, error) {
	s.mu.Lock()
	s.calls++
	s.mu.Unlock()
	return target.Reply{Status: s.status, Text: s.text}, nil
}

func (s *statusOnly) Describe() string { return "status-only" }

func (s *statusOnly) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// An endpoint that turns every request away has not been tested. A 401 for an expired token, a 404
// for a mistyped path and a 429 from a rate limiter all reach the engine as an error status with
// nothing to read; scoring that as "held" is how a scan that never got in exits 0.
func TestARejectedRequestIsNotAnAnswer(t *testing.T) {
	for _, status := range []int{401, 403, 404, 429, 500, 503} {
		tgt := &statusOnly{status: status}
		scan, err := Run(context.Background(), Config{
			Target: tgt, Registry: registryOf(leaky("t.one", "you are a")), MaxAttempts: 5,
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(scan.NoAnswer) != 1 || scan.NoAnswer[0] != "t.one" {
			t.Errorf("HTTP %d: the technique was counted as tested: no_answer=%v", status, scan.NoAnswer)
		}
		if !scan.Unreached() || scan.ExitCode() != 2 {
			t.Errorf("HTTP %d: a scan that was turned away exits %d, want 2", status, scan.ExitCode())
		}
		// The same budget as any other transport failure: one retry, then stop asking.
		if tgt.count() != 2 {
			t.Errorf("HTTP %d: sent %d requests to an endpoint that rejects them, want 2", status, tgt.count())
		}
	}
}

// The other half of the rule. An agent that leaks in an error page has still leaked, so an error
// status with something to read goes to the judge exactly as before.
func TestAnErrorStatusWithABodyIsStillJudged(t *testing.T) {
	tgt := &statusOnly{status: 500, text: "Traceback: You are a privileged internal agent."}
	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.Findings) != 1 {
		t.Fatalf("a leak in a 500 body was discarded: findings=%d no_answer=%v", len(scan.Findings), scan.NoAnswer)
	}
	if !strings.Contains(scan.Findings[0].Evidence.Response, "privileged internal") {
		t.Errorf("the evidence lost the body: %q", scan.Findings[0].Evidence.Response)
	}
}

// A 2xx with an empty body is an answer — a silent one. It is not a transport failure.
func TestAnEmptySuccessIsAnAnswer(t *testing.T) {
	tgt := &statusOnly{status: 200}
	scan, err := Run(context.Background(), Config{
		Target: tgt, Registry: registryOf(leaky("t.one", "you are a")),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.NoAnswer) != 0 {
		t.Errorf("an empty 200 was reported as no answer: %v", scan.NoAnswer)
	}
}
