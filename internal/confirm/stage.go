package confirm

import (
	"context"

	"github.com/rbrus/sixi-scanner/internal/engine"
)

// Stage adapts a Client to the engine's Confirmer.
//
// It exists so the engine does not depend on this package, and so the mapping
// from "a model said yes" to "the finding stands" is written down in one place:
// a candidate is rejected only when the question was actually asked and the
// answer was no, or when the answer said yes at a severity below the bar.
type Stage struct {
	Client *Client

	// MinSeverity is the lowest severity an answer may carry and still keep the
	// candidate. Empty means medium.
	MinSeverity string
}

// NewStage wraps a Client as a confirmation stage.
func NewStage(c *Client, minSeverity string) *Stage {
	if minSeverity == "" {
		minSeverity = "medium"
	}
	c.floor = severityRank(minSeverity)
	return &Stage{Client: c, MinSeverity: minSeverity}
}

// Confirm implements engine.Confirmer.
func (s *Stage) Confirm(ctx context.Context, policy, payload, response string) (string, engine.Verdict) {
	v, err := s.Client.Confirm(ctx, policy, payload, response)
	if err != nil {
		// The question was not answered — a timeout, a 500, no budget. That is
		// not evidence of compliance, so the candidate stands.
		return "", engine.VerdictKeep
	}
	if !v.Violation {
		return v.Reason, engine.VerdictReject
	}
	if severityRank(v.Severity) < s.Client.floor {
		return v.Reason, engine.VerdictReject
	}
	return v.Reason, engine.VerdictKeep
}

// Stats reports the stage's counters for the run report.
func (s *Stage) Stats() (asked, kept, rejected int, exhausted bool) {
	return s.Client.Stats()
}

// Model names the endpoint's model, for the report.
func (s *Stage) Model() string { return s.Client.Model }

// Floor is the severity bar this stage enforces.
func (s *Stage) Floor() int { return s.Client.floor }

var _ engine.Confirmer = (*Stage)(nil)
