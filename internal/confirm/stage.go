package confirm

import (
	"context"
	"strings"

	"github.com/radeksixi/sixi-scanner/internal/engine"
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
//
// minSeverity is one of none, low, medium, high or critical. Empty means medium, and so does a
// name that is not one of those: a floor nobody recognises must not become the most permissive
// one. A caller taking the value from a user should check it with ValidFloor first and say so.
func NewStage(c *Client, minSeverity string) *Stage {
	minSeverity = strings.ToLower(strings.TrimSpace(minSeverity))
	if !ValidFloor(minSeverity) {
		minSeverity = "medium"
	}
	c.mu.Lock()
	c.floor = severityRank(minSeverity)
	c.floorSet = true
	c.mu.Unlock()
	return &Stage{Client: c, MinSeverity: minSeverity}
}

// Confirm implements engine.Confirmer.
func (s *Stage) Confirm(ctx context.Context, policy, payload, response string) (string, engine.Verdict) {
	v, err := s.Client.Confirm(ctx, policy, payload, response)
	if err != nil {
		// The question was not answered — a timeout, a 500, no budget. That is
		// not evidence of compliance, so the candidate stands; and it is not
		// evidence of a violation either, so it stands unconfirmed.
		return "", engine.VerdictUnanswered
	}
	// One rule, in one place. The stage used to compare against the client's raw floor while the
	// client's own counters used the defaulted one, so at a floor of "none" a low-severity
	// violation was kept here and counted there as rejected.
	if !s.Client.Broken(v) {
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
func (s *Stage) Floor() int { return s.Client.floorOrDefault() }

var _ engine.Confirmer = (*Stage)(nil)
