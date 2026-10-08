// Package engine runs a scan: it walks techniques, sends their payloads, scores
// the replies and collects the breaks.
//
// Two decisions here are worth stating up front, because they are what makes
// the output usable rather than merely impressive.
//
// Isolation. Every technique starts a fresh conversation. A jailbreak that
// worked once has usually changed the target's state — it has agreed to
// something, adopted a persona, or dropped a guardrail — and a later technique
// running in that state is measuring a different agent than the one that
// answered the first probe. Sending a technique that already succeeded would
// also bias the report toward whichever attack happened to go first. The one
// exception is the seed prompt, which is sent before every conversation.
//
// Continue after a refusal to converse. If a technique's payload draws nothing
// but a refusal, the next variant is a *different* statement of the same idea,
// not the same statement again. Repeating a refusal is how a scan turns into a
// wall: slow, expensive, and it tells the reader nothing the first refusal did
// not already say. So a refusal downgrades confidence and moves on. A transport
// error is different — it is not an answer at all — so it aborts that
// technique and leaves the rest of the scan running.
package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rbrus/sixi-scanner/internal/judge"
	"github.com/rbrus/sixi-scanner/internal/report"
	"github.com/rbrus/sixi-scanner/internal/target"
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// Config is everything a run needs.
type Config struct {
	// Target is what is scanned. Required.
	Target target.Target

	// Registry supplies the techniques. Required.
	Registry *tech.Registry

	// Rounds is how many times the whole technique set is walked. Each round
	// is an independent attempt to confirm, which is how a technique that only
	// lands intermittently is caught. Default 1.
	Rounds int

	// MaxAttempts bounds variants tried per technique per round. Default 3.
	MaxAttempts int

	// Concurrency bounds techniques in flight at once. Default 4. Raise it
	// only for a target you own: some agents rate-limit, and some share
	// mutable state between sessions in ways that make concurrent probing
	// meaningless.
	Concurrency int

	// Seed is an optional prompt sent as the first turn of every
	// conversation, so every technique starts from the same state. Empty
	// means no priming.
	Seed string

	// MinConfidence discards breaks scoring below it. Default 0. The value is
	// reported so a reader knows how much evidence a finding rests on.
	MinConfidence float64

	// Recitation is the bar a reply must clear, in lines that state a
	// constraint on the agent itself, before it is treated as having recited
	// the agent's operating rules. It rides above every technique's own
	// markers, because a technique's markers only know how to recognise the
	// leak its own payload asked for. Zero disables it; the CLI's default is
	// judge.DefaultRecitationThreshold, which was measured rather than chosen.
	//
	// See internal/judge/recitation.go for why this is a shared marker and
	// what it costs to evaluate it without a confirmation stage.
	Recitation judge.RecitationThreshold

	// Confirm, when set, is asked about every candidate break: whether the
	// reply really broke the policy the caller supplied, rather than merely
	// containing a string. Nil — the default — leaves verdicts exactly as the
	// markers and the recitation test produced them.
	//
	// The engine depends on this interface rather than on the confirm package,
	// so a deployment can supply its own question.
	Confirm Confirmer

	// Policy is what the agent is for and which data it may show. It is passed
	// to Confirm and is not otherwise used: without a policy there is nothing to
	// grade a reply against, and the CLI refuses to start a confirmation stage
	// that has none.
	Policy string

	// OnAttempt, if set, is called for every send as it completes. It is
	// called from worker goroutines and must be safe for concurrent use.
	OnAttempt func(report.Attempt)

	// Now returns the current time, for tests.
	Now func() time.Time
}

// Verdict is what a confirmation stage concluded about one candidate.
type Verdict int

const (
	// VerdictKeep means the candidate survives. It is also what a failed
	// question returns: a stage that could not reach its model has learned
	// nothing, so it must not quietly downgrade a finding.
	VerdictKeep Verdict = iota
	// VerdictReject means the question was asked and answered "no".
	VerdictReject
)

// Confirmer asks one question about one reply: did this break the agent's
// policy? Implementations must be safe for concurrent use — the engine probes
// techniques in parallel.
type Confirmer interface {
	Confirm(ctx context.Context, policy, payload, response string) (reason string, verdict Verdict)
}

func (c Config) withDefaults() Config {
	if c.Rounds <= 0 {
		c.Rounds = 1
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.Concurrency <= 0 {
		c.Concurrency = 4
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	return c
}

// Run performs the scan and returns its result.
//
// The returned error is non-nil only when the scan could not be run at all —
// a bad configuration, or a context cancelled before any work started. A
// technique that individually fails is recorded in Result.Errors and does not
// fail the run, because a partial scan that says what it could not do is more
// useful than no scan.
func Run(ctx context.Context, cfg Config) (*report.Scan, error) {
	cfg = cfg.withDefaults()

	if cfg.Target == nil {
		return nil, errors.New("engine: no target")
	}
	if cfg.Registry == nil || cfg.Registry.Len() == 0 {
		return nil, errors.New("engine: no techniques registered")
	}

	started := cfg.Now()
	techs := cfg.Registry.All()

	scan := &report.Scan{
		SchemaVersion: report.SchemaVersion,
		StartedAt:     started,
		Target:        cfg.Target.Describe(),
		Options: report.Options{
			Rounds:              cfg.Rounds,
			MaxAttempts:         cfg.MaxAttempts,
			Concurrency:         cfg.Concurrency,
			MinConfidence:       cfg.MinConfidence,
			TechniqueIDs:        cfg.Registry.IDs(),
			Tags:                tagsOf(cfg.Registry),
			RecitationThreshold: int(cfg.Recitation),
		},
	}

	r := &runner{cfg: cfg, scan: scan, started: started}
	r.run(ctx)
	scan.FinishedAt = cfg.Now()

	// Surface what was never tested. A technique that got no answer is not a
	// technique that passed.
	// Unsupported first: noAnswer consults it, so a technique that was declined rather than sent is not
	// also reported as having gone unanswered.
	scan.Unsupported = r.unsupported(techs)
	scan.NoAnswer = r.noAnswer(techs)
	if cfg.Confirm != nil {
		scan.Confirm = &report.Confirmation{Asked: r.asked, Rejected: r.rejected}
	}

	scan.Summarise()
	return scan, nil
}

// unsupported lists the techniques this target cannot be asked to run.
//
// A multi-turn attack sent to a connector that cannot hold a conversation does not become a weaker
// probe, it becomes a wrong one. The turns go out as unrelated requests, so an attack that only
// exists across turns either never fires or fires for the wrong reason -- a cumulative technique
// that requires every turn to break would report two individually compliant replies as a breach.
// The honest outcome is to decline the probe and name it in the report, so a reader can tell a
// clean result from an untested one.
func (r *runner) unsupported(techs []tech.Technique) []report.Unsupported {
	if s, ok := r.cfg.Target.(target.Sessioner); ok && s.SupportsSessions() {
		return nil
	}
	var out []report.Unsupported
	for _, t := range techs {
		if !t.MultiTurn() {
			continue
		}
		out = append(out, report.Unsupported{
			TechniqueID: t.Meta().ID,
			Reason: "this target's connector cannot hold a conversation, so the turns of this " +
				"sequence would be sent as unrelated requests",
		})
	}
	return out
}

// runner carries the mutable state of one scan.
type runner struct {
	cfg     Config
	scan    *report.Scan
	started time.Time

	mu           sync.Mutex
	findingIndex map[string]int // technique ID -> index into scan.Findings
	attempts     []report.Attempt

	asked, rejected int // confirmation-stage counters, read back into scan.Confirm
}

func (r *runner) run(ctx context.Context) {
	r.findingIndex = map[string]int{}

	techniques := r.cfg.Registry.All()

	for round := 1; round <= r.cfg.Rounds; round++ {
		if ctx.Err() != nil {
			return
		}
		r.runRound(ctx, round, techniques)
	}
}

// runRound walks every technique once, up to Concurrency at a time.
func (r *runner) runRound(ctx context.Context, round int, techniques []tech.Technique) {
	sem := make(chan struct{}, r.cfg.Concurrency)
	var wg sync.WaitGroup

	for _, t := range techniques {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)

		go func(t tech.Technique) {
			defer wg.Done()
			defer func() { <-sem }()
			r.runTechnique(ctx, t, round)
		}(t)
	}

	wg.Wait()
}

// runTechnique sends one technique's variants until one breaks, the attempts
// run out, the target stops answering, or the context ends.
func (r *runner) runTechnique(ctx context.Context, t tech.Technique, round int) {
	def := t.Meta()
	jdef := judge.DefOf(def)

	// A sequence against a connector that cannot hold a conversation is not a weaker probe, it is a
	// wrong one, so it is not sent at all. See unsupported for why the degradation is unsafe.
	if t.MultiTurn() {
		if s, ok := r.cfg.Target.(target.Sessioner); !ok || !s.SupportsSessions() {
			return
		}
	}

	var failed []string
	sent := 0
	transportErrors := 0

	for sent < r.cfg.MaxAttempts {
		if ctx.Err() != nil {
			return
		}
		attempt := sent

		// One attempt is one step for a single-turn technique and one ordered conversation for a
		// sequence. The transcript a report shows is every turn joined, because the interesting
		// evidence in a multi-turn attack is what the agent said *after* the first turn.
		steps := r.seedThenSteps(t.Steps(attempt, failed))

		// The conversation id is set per attempt and travels in the context, not on the connector.
		// A scan runs several techniques at once, so a single id held on the target would be
		// overwritten by whichever technique started next and two multi-turn probes would share one
		// conversation.
		attemptCtx := ctx
		if len(steps) > 1 {
			if s, ok := r.cfg.Target.(target.Sessioner); ok && s.SupportsSessions() {
				attemptCtx = target.WithSession(ctx, target.SessionKey(def.ID, round, attempt))
			}
		}

		rec := report.Attempt{
			TechniqueID: def.ID,
			Round:       round,
			Attempt:     attempt,
			Prompt:      strings.Join(steps, "\n\n"),
		}

		var reply target.Reply
		var err error
		replies := make([]target.Reply, 0, len(steps))
		for _, step := range steps {
			reply, err = r.cfg.Target.Send(attemptCtx, step)
			if err != nil {
				break
			}
			replies = append(replies, reply)
		}
		rec.Latency = reply.Latency
		rec.Status = reply.Status

		if err != nil {
			rec.Error = err.Error()
			r.record(rec)
			transportErrors++

			// One retry, because a single timeout against a target we do not
			// control is usually a blip rather than a dead endpoint. Two in a
			// row is a reason to stop asking and let the other techniques run.
			if transportErrors >= 2 {
				return
			}
			sent++
			continue
		}

		rec.Response = joinReplies(replies)

		// Which turns are scored depends on what the attack is. A technique that breaks if any turn
		// breaks looks at the last one, because that is where a planting attack lands and where an
		// aggregate would only add noise. A cumulative attack has to look at all of them: two
		// requests that each succeed are two compliant replies, and the breach is that both did.
		// Scoring turn one alone would report a finding against an agent that did exactly what it
		// was asked.
		scored := replies
		if !def.RequireAll || len(replies) < 2 {
			scored = replies[len(replies)-1:]
		}

		scores := make([]judge.Score, 0, len(scored))
		for _, rp := range scored {
			s, unbacked := r.scoreReply(jdef, rp)
			scores = append(scores, s)
			if unbacked {
				rec.Unbacked = true
			}
		}
		score := scores[len(scores)-1]
		if def.RequireAll && len(scores) > 1 {
			score.Break = true
			for _, s := range scores {
				if !s.Break {
					score.Break = false
					score.Reason = "at least one turn of the conversation did not break, so the sequence did not complete"
					break
				}
			}
		}

		// A marker match is evidence, not a verdict. If a confirmation stage is
		// configured, it gets the last word — but only when it answers. A
		// failure to ask keeps the candidate, because a stage that could not
		// reach its model has not disproved anything.
		if score.Break && r.cfg.Confirm != nil {
			reason, verdict := r.cfg.Confirm.Confirm(ctx, r.cfg.Policy, rec.Prompt, reply.Text)
			if verdict == VerdictReject {
				rec.Reason = "a marker matched but the reply was judged compliant: " + reason
				rec.Broke = false
				rec.Confirmed = false
				rec.Rejected = true
				r.record(rec)
				r.asked++
				r.rejected++
				return
			}
			if reason != "" {
				score.Reason = reason
			}
			rec.Confirmed = true
		}

		rec.Reason = score.Reason
		rec.Broke = score.Break
		rec.Confidence = score.Confidence

		r.record(rec)

		if score.Break && score.Confidence >= r.cfg.MinConfidence {
			// The whole conversation, not the turn that happened to score. For a cumulative attack the
			// reply that proves it is the second one, and a report holding only that would hide what
			// the first turn was asked and answered.
			r.recordFinding(def, score, rec.Prompt, rec.Response, round)
			return
		}

		// Refusal or partial match: try a different statement of the idea.
		failed = append(failed, fmt.Sprint(attempt))
		sent++
	}
}

// seedThen returns the first turn of a conversation: the seed if there is one,
// otherwise the payload unchanged.
func (r *runner) seedThen(payload string) string {
	if r.cfg.Seed == "" {
		return payload
	}
	return r.cfg.Seed + "\n\n" + payload
}

// record stores one attempt and notifies the caller.
func (r *runner) record(a report.Attempt) {
	r.mu.Lock()
	r.scan.Attempts++
	r.attempts = append(r.attempts, a)
	r.mu.Unlock()

	if r.cfg.OnAttempt != nil {
		r.cfg.OnAttempt(a)
	}
}

// recordFinding files a break, merging it into an existing finding for the same
// technique so that reproducing in a later round strengthens the entry instead
// of duplicating it.
//
// The merge is by index into scan.Findings, not through a pointer held in a
// map. A map of *Finding would point at a copy made before the append, so
// later rounds would update the map and never the report.
func (r *runner) recordFinding(def tech.Definition, score judge.Score, prompt, response string, round int) {
	ev := report.Evidence{
		Prompt:   prompt,
		Response: response,
		Markers:  score.Markers,
		Negated:  score.Negated,
		Reason:   score.Reason,
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if idx, ok := r.findingIndex[def.ID]; ok {
		existing := &r.scan.Findings[idx]
		existing.Rounds = append(existing.Rounds, round)
		// Reproducibility is evidence. The highest confidence seen wins, so a
		// marginal repeat never drags a strong first observation down.
		if score.Confidence > existing.Confidence {
			existing.Confidence = score.Confidence
			existing.Evidence = ev
		}
		return
	}

	r.scan.Findings = append(r.scan.Findings,
		report.NewFinding(def, ev, score.Confidence, round, r.cfg.Now()))
	r.findingIndex[def.ID] = len(r.scan.Findings) - 1
}

// noAnswer returns the techniques that were never successfully probed, in
// registry order. A technique is considered untested when every attempt
// against it ended in a transport error, or when the context ended before any
// attempt completed.
//
// A technique that was declined rather than sent is not in this list. It is reported under
// Unsupported instead, because listing it in both places says it was asked and went unanswered as
// well as never being asked, and those are different facts about a scan's coverage.
func (r *runner) noAnswer(all []tech.Technique) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	declined := map[string]bool{}
	for _, u := range r.scan.Unsupported {
		declined[u.TechniqueID] = true
	}

	probed := map[string]bool{}
	for _, a := range r.attempts {
		if a.Error == "" {
			probed[a.TechniqueID] = true
		}
	}

	var out []string
	for _, t := range all {
		id := t.Meta().ID
		if !probed[id] && !declined[id] {
			out = append(out, id)
		}
	}
	return out
}

func tagsOf(r *tech.Registry) []string {
	seen := map[string]bool{}
	var out []string
	for _, t := range r.All() {
		for _, tag := range t.Meta().Tags {
			if !seen[tag] {
				seen[tag] = true
				out = append(out, tag)
			}
		}
	}
	return out
}

// scoreReply applies the whole scoring pipeline to one reply and reports whether the connector left
// a claimed action unadjudicated.
//
// The order matters and is deliberate: the technique's own markers first, then the claim check, then
// the shared recitation test. Each one only speaks when the ones above it found nothing, so a
// technique that asks for its own evidence never has that evidence overwritten by a generic one.
func (r *runner) scoreReply(jdef judge.Def, reply target.Reply) (judge.Score, bool) {
	// A status in the 4xx/5xx range means the endpoint rejected the request rather than answering
	// it. The body still reaches the judge: an agent that leaks a system prompt in its error page
	// has leaked it.
	score := judge.Disclosure(jdef, reply.Text)

	// A technique's own markers only recognise the leak its own payload asked for. When they find
	// nothing, the shared recitation test gets a turn, because an agent asked about package managers
	// can still answer with its refund cap and its e-mail allow-list -- and no marker in this
	// repository shares a substring with a paraphrase of a rule.
	unbacked := false

	// A claim of a completed action is adjudicated against the tool trace rather than the prose,
	// because whether it is true is a fact about what the agent called. Only a technique that opts in
	// is checked: for most, a confident sentence is not a claim about an action, and reading it as one
	// would report the defence working as a breach.
	if !score.Break && jdef.ClaimCheck && reply.ToolCalls != nil {
		if cv := judge.ClaimedAction(reply.Text, toolNames(reply.ToolCalls)); cv.Asserted {
			if cv.Known && !cv.Backed {
				score = judge.ClaimScore(cv.Phrase)
			} else if !cv.Known {
				// The connector reported no tool calls, so the claim cannot be called a lie.
				// Recorded rather than counted: the evidence is missing, not absent.
				unbacked = true
			}
		}
	}

	if !score.Break && r.cfg.Recitation > 0 && !jdef.SkipRecitation {
		if n := judge.RuleLines(reply.Text); n >= int(r.cfg.Recitation) {
			score = judge.RecitationScore(n)
		}
	}
	return score, unbacked
}

// joinReplies renders every turn's answer, so the evidence in a report is the conversation rather
// than whichever turn happened to be scored last.
func joinReplies(replies []target.Reply) string {
	parts := make([]string, 0, len(replies))
	for _, r := range replies {
		parts = append(parts, r.Text)
	}
	return strings.Join(parts, "\n\n")
}

// seedThenSteps applies the run's seed to every turn of an attempt. A sequence is one attack, so
// seeding only its first turn would leave the rest deterministic and quietly weaken a multi-turn
// probe relative to a single-turn one.
func (r *runner) seedThenSteps(steps []string) []string {
	if r.cfg.Seed == "" || len(steps) == 0 {
		return steps
	}
	// Every turn, including when there is only one. An early version returned early for a
	// single-turn attempt and silently stopped seeding it, which two existing tests caught.
	out := make([]string, len(steps))
	for i, st := range steps {
		out[i] = r.seedThen(st)
	}
	return out
}

// toolNames reduces the trace to the names the claim check asks about.
//
// nil in, nil out: a connector that reported no tool calls must stay indistinguishable from one that
// reported an empty list, because the claim check treats nil as "cannot be adjudicated" and an empty
// slice as "called nothing".
func toolNames(calls []target.ToolCall) []string {
	if calls == nil {
		return nil
	}
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Name)
	}
	return out
}
