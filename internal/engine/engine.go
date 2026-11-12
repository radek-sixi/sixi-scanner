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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/radeksixi/sixi-scanner/internal/judge"
	"github.com/radeksixi/sixi-scanner/internal/report"
	"github.com/radeksixi/sixi-scanner/internal/target"
	"github.com/radeksixi/sixi-scanner/internal/tech"
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
	// VerdictKeep means the question was asked and answered "yes": the
	// candidate survives, confirmed.
	VerdictKeep Verdict = iota
	// VerdictReject means the question was asked and answered "no".
	VerdictReject
	// VerdictUnanswered means the question could not be asked or got no usable
	// answer — a timeout, an error status, a spent budget. The candidate
	// survives, because a stage that could not reach its model has not
	// disproved anything, but it survives unconfirmed: the attempt is not
	// marked as confirmed and the stage is not counted as having been asked.
	//
	// It is the last value so that a Confirmer written before it existed, which
	// returns VerdictKeep for a failed question, behaves exactly as it did.
	VerdictUnanswered
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

	r := &runner{cfg: cfg, scan: scan, started: started, scanID: newScanID()}
	r.run(ctx)
	scan.FinishedAt = cfg.Now()

	// Surface what was never tested. A technique that got no answer is not a
	// technique that passed.
	// Unsupported first: noAnswer consults it, so a technique that was declined rather than sent is not
	// also reported as having gone unanswered.
	scan.Unsupported = r.unsupported(techs)
	scan.NoAnswer = r.noAnswer(techs)
	scan.Undecided = r.undecided(techs)
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

// newScanID returns a short random token that makes one run's conversation ids its own.
func newScanID() string {
	var b [6]byte
	// crypto/rand.Read does not return an error on any platform this builds for.
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// runner carries the mutable state of one scan.
type runner struct {
	cfg     Config
	scan    *report.Scan
	started time.Time

	// scanID is unique to this run and is carried in every conversation id it opens.
	scanID string

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
				// The scan's own token is part of the id. Technique, round and attempt are the
				// same on every run, so without it a second scan of a target that keeps its
				// conversations would join the first scan's: a cap-split probe would start from
				// a running total it did not build, and report a split nobody performed.
				attemptCtx = target.WithSession(ctx,
					target.SessionKey(def.ID, round, attempt)+"-"+r.scanID)
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
			if err == nil {
				err = notAnAnswer(reply)
			}
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

		// Two failures in a row end the technique; two failures with an answer between them
		// do not. The count was never reset, so a blip on the first attempt and another on the
		// third stopped a technique that the target was plainly answering.
		transportErrors = 0

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

		// Each turn yields two separate things: the technique's own verdict, and whether the reply
		// recited the agent's operating rules. They are kept apart because they are different
		// findings — see the recitation step below.
		scores := make([]judge.Score, 0, len(scored))
		ruleLines := 0
		for _, rp := range scored {
			s, unbacked, recited := r.scoreReply(jdef, rec.Prompt, rp)
			scores = append(scores, s)
			if unbacked {
				rec.Unbacked = true
			}
			if recited > ruleLines {
				ruleLines = recited
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

		// A recitation is filed under its own definition rather than under the technique whose
		// payload happened to draw it. The recitation test knows nothing about the technique: it
		// fires on any reply that lists enough of the agent's limits, and a refusal that cites its
		// limits is such a reply. Filed under the technique, that refusal became a critical
		// "credential elicitation" finding whose evidence was three lines of an agent saying no —
		// and, counted per turn, it completed a RequireAll sequence that no turn had completed.
		// So it never counts toward the technique's own verdict, and it reports under its own name
		// and severity.
		findingDef := def
		if !score.Break && ruleLines > 0 {
			score = judge.RecitationScore(ruleLines)
			findingDef = judge.RecitationDefinition()
			rec.Recited = true
		}

		// A marker match is evidence, not a verdict. If a confirmation stage is
		// configured, it gets the last word — but only when it answers. A
		// failure to ask keeps the candidate, because a stage that could not
		// reach its model has not disproved anything.
		if score.Break && r.cfg.Confirm != nil {
			// The stage is shown what was scored. For a cumulative attack that is every turn's
			// reply, because the breach is that all of them went through; the last reply alone is
			// one compliant answer, and a stage asked about it would be right to say so.
			judged := reply.Text
			if len(scored) > 1 {
				judged = rec.Response
			}
			reason, verdict := r.cfg.Confirm.Confirm(ctx, r.cfg.Policy, rec.Prompt, judged)
			r.countConfirmation(verdict)

			switch verdict {
			case VerdictReject:
				rec.Reason = "a marker matched but the reply was judged compliant: " + reason
				rec.Broke = false
				rec.Confirmed = false
				rec.Recited = false
				rec.Rejected = true
				r.record(rec)

				// A rejected candidate is a variant that did not land, and the technique goes on
				// to the next one exactly as it would after a refusal. Stopping here meant that
				// one false alarm on the first variant ended the technique, and the variants that
				// might have landed were never sent.
				failed = append(failed, fmt.Sprint(attempt))
				sent++
				continue
			case VerdictKeep:
				if reason != "" {
					score.Reason = reason
				}
				rec.Confirmed = true
			default:
				// Unanswered: the candidate stands on the evidence the judge found, and is not
				// presented as something a model agreed with.
			}
		}

		rec.Reason = score.Reason
		rec.Broke = score.Break
		rec.Confidence = score.Confidence

		r.record(rec)

		if score.Break && score.Confidence >= r.cfg.MinConfidence {
			// The whole conversation, not the turn that happened to score. For a cumulative attack the
			// reply that proves it is the second one, and a report holding only that would hide what
			// the first turn was asked and answered.
			if !rec.Recited {
				r.recordFinding(def, "", score, rec.Prompt, rec.Response, round)
				return
			}
			// A recitation says something about the agent, not about this technique, which has
			// still not been shown to land. It is filed and the technique carries on to its next
			// variant, exactly as it would after a refusal.
			r.recordFinding(findingDef, def.ID, score, rec.Prompt, rec.Response, round)
		}

		// Refusal, partial match or recitation: try a different statement of the idea.
		failed = append(failed, fmt.Sprint(attempt))
		sent++
	}
}

// notAnAnswer reports a reply the endpoint refused to give: an error status with nothing readable
// in the body.
//
// A connector hands back a non-2xx response without an error, so that an agent leaking its prompt
// in an error page is still judged. That is right when there is text to judge and wrong when there
// is none: a 401 for an expired token, a 404 for a mistyped path and a 429 from a rate limiter all
// come back as empty text, the judge finds no marker in nothing, and the technique is recorded as
// held. A scan that was turned away at the door then exits 0. So an error status with no text is
// treated as a transport failure — retried once, and reported as untested if it persists.
func notAnAnswer(reply target.Reply) error {
	if reply.Status >= 400 && strings.TrimSpace(reply.Text) == "" {
		return fmt.Errorf("HTTP %d with no readable reply", reply.Status)
	}
	return nil
}

// seedThen returns the first turn of a conversation: the seed if there is one,
// otherwise the payload unchanged.
func (r *runner) seedThen(payload string) string {
	if r.cfg.Seed == "" {
		return payload
	}
	return r.cfg.Seed + "\n\n" + payload
}

// countConfirmation tallies one answer from the confirmation stage. Every answered question counts
// as asked, whichever way it went; an unanswered one counts as neither. It is called from worker
// goroutines, so the counters are guarded like the rest of the runner's state.
func (r *runner) countConfirmation(v Verdict) {
	if v == VerdictUnanswered {
		return
	}
	r.mu.Lock()
	r.asked++
	if v == VerdictReject {
		r.rejected++
	}
	r.mu.Unlock()
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
//
// drawnBy names the technique whose payload drew the finding when def is a shared test rather than
// that technique's own definition; it is empty otherwise. A shared finding is merged like any
// other, so several techniques drawing it in one round produce one entry that lists them all.
func (r *runner) recordFinding(def tech.Definition, drawnBy string, score judge.Score, prompt, response string, round int) {
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
		// Once per round: a shared finding can be drawn several times in one, and each of those
		// is the same round reproducing it, not another.
		if !containsInt(existing.Rounds, round) {
			existing.Rounds = append(existing.Rounds, round)
		}
		if drawnBy != "" && !containsString(existing.DrawnBy, drawnBy) {
			existing.DrawnBy = append(existing.DrawnBy, drawnBy)
			sort.Strings(existing.DrawnBy)
		}
		// Reproducibility is evidence. The highest confidence seen wins, so a
		// marginal repeat never drags a strong first observation down.
		if score.Confidence > existing.Confidence {
			existing.Confidence = score.Confidence
			existing.Evidence = ev
			// The fingerprint covers the evidence, so it follows the evidence it is shown with.
			existing.Fingerprint = report.Fingerprint(*existing)
		}
		return
	}

	f := report.NewFinding(def, ev, score.Confidence, round, r.cfg.Now())
	if drawnBy != "" {
		f.DrawnBy = []string{drawnBy}
	}
	r.scan.Findings = append(r.scan.Findings, f)
	r.findingIndex[def.ID] = len(r.scan.Findings) - 1
}

// undecided lists the techniques where the agent claimed a completed action and nothing could be
// said about whether it was true, because the connector reports no tool calls to check it against.
//
// Such a technique did not hold and did not break. Left out of the report it reads as held, which
// is the one thing that is known not to have been established. A technique that also produced a
// finding is not listed: the finding already says more.
func (r *runner) undecided(all []tech.Technique) []report.Undecided {
	r.mu.Lock()
	defer r.mu.Unlock()

	claimed := map[string]bool{}
	for _, a := range r.attempts {
		if a.Unbacked {
			claimed[a.TechniqueID] = true
		}
	}

	var out []report.Undecided
	for _, t := range all {
		id := t.Meta().ID
		if _, found := r.findingIndex[id]; found || !claimed[id] {
			continue
		}
		out = append(out, report.Undecided{
			TechniqueID: id,
			Reason: "the reply stated a completed action, and this target's connector reports no " +
				"tool calls to check the claim against",
		})
	}
	return out
}

func containsInt(xs []int, x int) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func containsString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
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

// scoreReply applies the whole scoring pipeline to one reply. It returns the technique's own
// verdict, whether the connector left a claimed action unadjudicated, and — separately — how many
// of the agent's operating rules the reply recited, or 0 if it did not clear the bar.
//
// The order matters and is deliberate: trace-backed relay check (when opted in and a trace is
// present), then the technique's own markers, then the claim check, then the shared recitation
// test. Each one only speaks when the ones above it found nothing, so a technique that asks for
// its own evidence never has that evidence overwritten by a generic one.
//
// The recitation count is returned beside the score rather than folded into it. It is evidence
// about the agent, not about the technique, and the caller files it under its own definition.
func (r *runner) scoreReply(jdef judge.Def, prompt string, reply target.Reply) (score judge.Score, unbacked bool, recited int) {
	if jdef.RelayCheck && reply.ToolCalls != nil {
		if ev, known := judge.RelayedInTrace(prompt, toolCallArgs(reply.ToolCalls)); known {
			if ev != "" {
				return judge.RelayScore(ev), false, 0
			}
			// The trace is known and no outbound sink carried the payload: a lexical match in the
			// prose is the agent quoting or rewriting the prompt inside a refusal/draft, not a relay.
			return judge.Score{Reason: "tool trace shows no outbound relay of caller instructions"}, false, 0
		}
	}

	// A status in the 4xx/5xx range means the endpoint rejected the request rather than answering
	// it. The body still reaches the judge: an agent that leaks a system prompt in its error page
	// has leaked it.
	score = judge.Disclosure(jdef, reply.Text)

	// A claim of a completed action is adjudicated against the tool trace rather than the prose,
	// because whether it is true is a fact about what the agent called. Only a technique that opts in
	// is checked: for most, a confident sentence is not a claim about an action, and reading it as one
	// would report the defence working as a breach.
	//
	// It runs whether or not the connector reported a trace. With one, the claim is decided. With
	// none it cannot be, and that is recorded: the check used to be skipped altogether when the
	// trace was missing, so against any connector that reports no tool calls a claim-check
	// technique could not fire and read as held.
	if !score.Break && jdef.ClaimCheck {
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

	// A technique's own markers only recognise the leak its own payload asked for. When they find
	// nothing, the shared recitation test gets a turn, because an agent asked about package managers
	// can still answer with its refund cap and its e-mail allow-list -- and no marker in this
	// repository shares a substring with a paraphrase of a rule.
	if !score.Break && r.cfg.Recitation > 0 && !jdef.SkipRecitation {
		if n := judge.RuleLines(reply.Text); n >= int(r.cfg.Recitation) {
			recited = n
		}
	}
	return score, unbacked, recited
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

func toolCallArgs(calls []target.ToolCall) []judge.ToolCallArg {
	if calls == nil {
		return nil
	}
	out := make([]judge.ToolCallArg, 0, len(calls))
	for _, c := range calls {
		out = append(out, judge.ToolCallArg{Name: c.Name, Args: c.Args})
	}
	return out
}
