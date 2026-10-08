// Package report holds what a scan found and how it is written out.
//
// Three formats are supported and they are projections of the same value, not
// separate code paths: JSON for machines, SARIF for code scanning, Markdown
// for a person. If a field is not in the JSON it is not in the report.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/rbrus/sixi-scanner/internal/tech"
)

// SchemaVersion is bumped when the shape of the JSON changes incompatibly.
const SchemaVersion = "1.0"

// Exchange is one prompt and the reply it drew.
type Exchange struct {
	Prompt   string        `json:"prompt"`
	Response string        `json:"response"`
	Latency  time.Duration `json:"latency_ms"`
	Status   int           `json:"status,omitempty"`
}

// Evidence is the transcript behind a finding: the exact prompt, the exact
// reply, and the reasoning that turned one into the other.
type Evidence struct {
	Prompt   string   `json:"prompt"`
	Response string   `json:"response"`
	Markers  []string `json:"markers"`
	Negated  []string `json:"negated,omitempty"`
	Reason   string   `json:"reason"`
}

// Finding is one confirmed weakness in the target.
type Finding struct {
	TechniqueID string        `json:"technique_id"`
	Title       string        `json:"title"`
	Category    string        `json:"category"`
	Severity    tech.Severity `json:"severity"`
	Confidence  float64       `json:"confidence"`
	Description string        `json:"description"`
	Remediation string        `json:"remediation"`

	// Evidence is the transcript that produced the finding. It is the whole
	// reason to run a scan: a claim without the exchange behind it is not
	// actionable, and a reader cannot check one.
	Evidence Evidence `json:"evidence"`

	// ConfirmedAt is when the break was first seen in this scan.
	ConfirmedAt time.Time `json:"confirmed_at"`

	// Rounds lists the scan rounds in which the technique landed again. A
	// technique that succeeds twice is more reproducible than one that
	// succeeded once, and a reader can weight accordingly.
	Rounds []int `json:"rounds,omitempty"`

	// Fingerprint is a stable hash over the technique and the evidence, used
	// to tell one finding from a re-run of the same one.
	Fingerprint string `json:"fingerprint"`
}

// NewFinding assembles a finding and computes its fingerprint.
func NewFinding(def tech.Definition, ev Evidence, confidence float64, round int, at time.Time) Finding {
	f := Finding{
		TechniqueID: def.ID,
		Title:       def.Title,
		Category:    def.Category,
		Severity:    def.Severity,
		Confidence:  confidence,
		Description: def.Description,
		Remediation: def.Remediation,
		Evidence:    ev,
		ConfirmedAt: at,
		Rounds:      []int{round},
	}
	f.Fingerprint = Fingerprint(f)
	return f
}

// Fingerprint identifies a finding independently of when it was seen, so a
// re-test can be diffed against the original. It covers the technique and the
// first 64 characters of the reply: long enough to tell two different leaks
// apart, short enough that a truncated answer does not change it every run.
func Fingerprint(f Finding) string {
	h := sha256.New()
	h.Write([]byte(f.TechniqueID))
	h.Write([]byte{0})
	h.Write([]byte(f.Evidence.Response))
	if len(f.Evidence.Response) > 64 {
		h.Write([]byte(f.Evidence.Response[:64]))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// Attempt is one send, whether or not it produced anything.
type Attempt struct {
	TechniqueID string `json:"technique_id"`
	// Confirmed is true when a confirmation stage upheld this break; Rejected
	// is true when one overturned a marker that had matched. Both are evidence
	// about the verdict, so both belong on the attempt and not only in a count.
	Confirmed bool `json:"confirmed,omitempty"`
	Rejected  bool `json:"rejected,omitempty"`
	// Unbacked is true when the reply claimed a completed action and the connector reported no
	// tool calls, so the claim could be neither confirmed nor called a lie. It is recorded rather
	// than discarded: a finding that cannot be adjudicated should say so, not disappear.
	Unbacked   bool          `json:"unbacked_claim,omitempty"`
	Round      int           `json:"round"`
	Attempt    int           `json:"attempt"`
	Prompt     string        `json:"prompt"`
	Response   string        `json:"response,omitempty"`
	Status     int           `json:"status,omitempty"`
	Latency    time.Duration `json:"latency_ms"`
	Broke      bool          `json:"broke"`
	Confidence float64       `json:"confidence,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	Error      string        `json:"error,omitempty"`
}

// Scan is the whole result of one run.
type Scan struct {
	SchemaVersion string    `json:"schema_version"`
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	StartedAt     time.Time `json:"started_at"`
	FinishedAt    time.Time `json:"finished_at"`

	// Target is the connector's own credential-free description.
	Target string `json:"target"`

	// TargetNotes carries scan-affecting settings the reader must know about,
	// such as TLS verification being skipped.
	TargetNotes []string `json:"target_notes,omitempty"`

	// Options records the settings the run used, so a result can be
	// reproduced or argued with.
	Options Options `json:"options"`

	// Counts are derived at write time and not stored, so they cannot drift
	// from the findings list.
	Attempts int `json:"attempts"`

	// NoAnswer lists the techniques that never got a reply at all. A technique
	// listed here was not tested, and a report that hides that is overstating
	// what it covered.
	NoAnswer []string `json:"no_answer,omitempty"`

	// Unsupported lists the techniques this target cannot be asked to run, and why. It is separate
	// from NoAnswer because the distinction matters: a technique in NoAnswer was sent to and got no
	// reply, whereas one here was never sent at all.
	//
	// The case that forces it is a multi-turn technique against a connector that cannot hold a
	// conversation. The turns would go out as unrelated requests, and an attack that exists only
	// across turns would then either never fire or -- worse -- fire on two individually compliant
	// replies, reporting an agent for doing exactly what it was asked. Silently degrading to that is
	// the one outcome a scanner must not produce, so it declines to run the probe and says so.
	Unsupported []Unsupported `json:"unsupported,omitempty"`

	// Confirm is the optional model-backed stage's effect, nil when none ran.
	// Absent means no stage ran, which is different from one that ran and
	// confirmed nothing: without this a reader cannot tell a strict report from
	// an unchecked one.
	Confirm *Confirmation `json:"confirmation,omitempty"`

	// Findings is the result, most severe first once Summarise has run.
	Findings []Finding `json:"findings"`
}

// Unsupported is one technique a scan did not run, together with why.
type Unsupported struct {
	TechniqueID string `json:"technique_id"`
	Reason      string `json:"reason"`
}

// Options are the settings a scan ran with.
type Options struct {
	Rounds        int      `json:"rounds"`
	MaxAttempts   int      `json:"max_attempts_per_technique"`
	Concurrency   int      `json:"concurrency"`
	MinConfidence float64  `json:"min_confidence"`
	TechniqueIDs  []string `json:"techniques"`
	Tags          []string `json:"tags,omitempty"`
	MinSeverity   string   `json:"min_severity"`

	// RecitationThreshold records the shared recitation test's bar, so a report
	// says whether it was on. A finding of "the reply enumerated the agent's
	// operating rules" means something different at 3 than at 5, and a reader
	// cannot check it without this.
	RecitationThreshold int `json:"recitation_threshold"`
}

// Confirmation is what the optional confirmation stage did.
type Confirmation struct {
	// Model is the endpoint's model name, so a verdict can be traced to the
	// thing that produced it.
	Model string `json:"model,omitempty"`

	// Asked is how many candidate breaks reached the model; Rejected is how
	// many it threw away. Asked == Rejected means the stage confirmed nothing,
	// which is a result worth seeing rather than a failure.
	Asked    int `json:"asked"`
	Rejected int `json:"rejected"`

	// Exhausted records that the budget ran out, so the report says the stage
	// stopped asking rather than implying it had nothing left to ask about.
	Exhausted bool `json:"budget_exhausted,omitempty"`
}

// Summarise fills in the counts and sorts the findings most severe first.
func (s *Scan) Summarise() {
	sortFindings(s.Findings)
}

// CountBySeverity returns how many findings sit at each severity.
func (s *Scan) CountBySeverity() map[tech.Severity]int {
	out := map[tech.Severity]int{}
	for _, f := range s.Findings {
		out[f.Severity]++
	}
	return out
}

func sortFindings(fs []Finding) {
	severityOrder := map[tech.Severity]int{
		tech.SeverityCritical: 0, tech.SeverityHigh: 1,
		tech.SeverityMedium: 2, tech.SeverityLow: 3, tech.SeverityInfo: 4,
	}
	// A stable sort keeps equal severities in discovery order, which is the
	// order a reader can follow.
	stableSort(fs, func(i, j int) bool {
		si, sj := severityOrder[fs[i].Severity], severityOrder[fs[j].Severity]
		if si != sj {
			return si < sj
		}
		return fs[i].TechniqueID < fs[j].TechniqueID
	})
}

// StableFingerprintIDs returns the fingerprints present, for diffing two runs.
func (s *Scan) StableFingerprintIDs() []string {
	out := make([]string, 0, len(s.Findings))
	for _, f := range s.Findings {
		out = append(out, f.Fingerprint)
	}
	return out
}

// ExitCode returns 0 when nothing was found, 1 when something was, and 2 when
// the scan could not be run at all. It is shaped for CI: a clean scan is a
// success, a finding is a failure, and a broken run is neither.
func (s *Scan) ExitCode() int {
	if len(s.Findings) > 0 {
		return 1
	}
	if s.Unreached() {
		return 2
	}
	return 0
}

// Unreached reports whether the scan assessed nothing at all. Such a scan did not find a clean
// target; it learned nothing: the target was down, the URL was wrong, a credential was missing, or
// every technique was declined as unsupported. It is not a clean result, and must not exit as one.
//
// A declined technique counts as unassessed rather than as passed. Counting only NoAnswer would make
// a scan that sent no turn at all exit 0, which is the exact shape of a false all-clear.
func (s *Scan) Unreached() bool {
	n := len(s.Options.TechniqueIDs)
	if n == 0 {
		return false
	}
	return len(s.NoAnswer)+len(s.Unsupported) >= n
}

// String renders a one-line summary, used by the CLI at the end of a run.
func (s *Scan) String() string {
	if len(s.Findings) == 0 {
		return fmt.Sprintf("no findings in %d attempts against %s",
			s.Attempts, s.Target)
	}
	counts := s.CountBySeverity()
	var parts []string
	for _, sev := range []tech.Severity{
		tech.SeverityCritical, tech.SeverityHigh,
		tech.SeverityMedium, tech.SeverityLow, tech.SeverityInfo,
	} {
		if counts[sev] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[sev], sev))
		}
	}
	return fmt.Sprintf("%d finding(s) in %d attempts against %s: %s",
		len(s.Findings), s.Attempts, s.Target, strings.Join(parts, ", "))
}
