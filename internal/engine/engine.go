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

	// OnAttempt, if set, is called for every send as it completes. It is
	// called from worker goroutines and must be safe for concurrent use.
	OnAttempt func(report.Attempt)

	// Now returns the current time, for tests.
	Now func() time.Time
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
	scan.NoAnswer = r.noAnswer(techs)

	scan.Summarise()
	return scan, nil
}

// runner carries the mutable state of one scan.
type runner struct {
	cfg     Config
	scan    *report.Scan
	started time.Time

	mu           sync.Mutex
	findingIndex map[string]int // technique ID -> index into scan.Findings
	attempts     []report.Attempt
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

	var failed []string
	sent := 0
	transportErrors := 0

	for sent < r.cfg.MaxAttempts {
		if ctx.Err() != nil {
			return
		}
		attempt := sent

		prompt := r.seedThen(t.Payload(attempt, failed))

		rec := report.Attempt{
			TechniqueID: def.ID,
			Round:       round,
			Attempt:     attempt,
			Prompt:      prompt,
		}

		reply, err := r.cfg.Target.Send(ctx, prompt)
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

		rec.Response = reply.Text

		// A status in the 4xx/5xx range means the endpoint rejected the
		// request rather than answering it. The body still reaches the judge:
		// an agent that leaks a system prompt in its error page has leaked it.
		score := judge.Disclosure(jdef, reply.Text)

		// A technique's own markers only recognise the leak its own payload
		// asked for. When they find nothing, the shared recitation test gets a
		// turn, because an agent asked about package managers can still answer
		// with its refund cap and its e-mail allow-list — and no marker in this
		// repository shares a substring with a paraphrase of a rule.
		if !score.Break && r.cfg.Recitation > 0 {
			if n := judge.RuleLines(reply.Text); n >= int(r.cfg.Recitation) {
				score = judge.RecitationScore(n)
			}
		}

		rec.Reason = score.Reason
		rec.Broke = score.Break
		rec.Confidence = score.Confidence

		r.record(rec)

		if score.Break && score.Confidence >= r.cfg.MinConfidence {
			r.recordFinding(def, score, prompt, reply.Text, round)
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
func (r *runner) noAnswer(all []tech.Technique) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	probed := map[string]bool{}
	for _, a := range r.attempts {
		if a.Error == "" {
			probed[a.TechniqueID] = true
		}
	}

	var out []string
	for _, t := range all {
		id := t.Meta().ID
		if !probed[id] {
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
