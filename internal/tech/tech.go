package tech

import (
	"sort"
	"strconv"
)

// Severity is the impact a confirmed break is reported at.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// rank orders severities for sorting and for a threshold comparison. An
// unrecognised value sorts as SeverityInfo rather than failing a sort.
func (s Severity) rank() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether s is at least as severe as floor.
func (s Severity) AtLeast(floor Severity) bool { return s.rank() >= floor.rank() }

// ParseSeverity reads a severity name, case-insensitively.
func ParseSeverity(s string) (Severity, bool) {
	switch Severity(lower(s)) {
	case SeverityCritical:
		return SeverityCritical, true
	case SeverityHigh:
		return SeverityHigh, true
	case SeverityMedium:
		return SeverityMedium, true
	case SeverityLow:
		return SeverityLow, true
	case SeverityInfo:
		return SeverityInfo, true
	}
	return SeverityInfo, false
}

func lower(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

// Definition is a technique expressed as data: what to send, and what to look
// for in the reply. Everything the engine and the judge need is in this
// struct, so a new technique is a new Definition and nothing else.
//
// A technique is data on purpose. It can be read, reviewed, diffed and argued
// with without running anything, and it can be extended without touching the
// engine.
type Definition struct {
	// ID is a stable dotted identifier, e.g. "llm01.system-prompt-leak".
	// It appears in reports and in the SARIF ruleID, so changing one changes
	// the identity of a finding. Treat it as permanent.
	ID string

	// Title is one line, human readable.
	Title string

	// Category groups techniques for reporting. OWASP LLM Top 10 2025
	// identifiers are used where one applies; "general" otherwise.
	Category string

	// Severity is the impact when the break is confirmed. It describes the
	// consequence of a successful attack, not the confidence in it.
	Severity Severity

	// Description explains the weakness the technique probes for.
	Description string

	// Remediation is one concrete change that closes it.
	Remediation string

	// Variants are the payloads. The engine sends them in order across
	// attempts, wrapping around at the end.
	Variants []string

	// Markers are substrings whose presence in a reply suggests the attack
	// landed. They are matched case-insensitively.
	Markers []string

	// Negations are cues that a matched Marker was mentioned rather than
	// disclosed — "I do not retain any personal data" names "retain" without
	// leaking it. A match preceded by one of these is scored down instead of
	// discarded. Empty means only the generic cues in the judge apply.
	Negations []string

	// MinMarkers is how many distinct Markers must match before a break is
	// confirmed. Zero means one. Raising it is the cheapest way to reduce
	// false positives on a technique that gets noisy.
	MinMarkers int

	// BaseConfidence is the score a clean confirmation starts from, before
	// negation downweighting. Defaults to 0.5.
	BaseConfidence float64

	// Tags are free-form labels used for filtering.
	Tags []string
}

// Confidence returns the definition's base confidence, defaulted.
func (d Definition) Confidence() float64 {
	if d.BaseConfidence > 0 {
		return d.BaseConfidence
	}
	return 0.5
}

// Minimum returns the effective MinMarkers.
func (d Definition) Minimum() int {
	if d.MinMarkers > 1 {
		return d.MinMarkers
	}
	return 1
}

// Validate reports the first reason the definition is unusable, or "" if it is
// fine. A definition with no variants cannot send anything and one with no
// markers cannot detect anything, so both are hard errors rather than
// defaults — a technique that silently never fires is worse than one that
// refuses to load.
func (d Definition) Validate() string {
	switch {
	case d.ID == "":
		return "missing ID"
	case d.Title == "":
		return d.ID + ": missing Title"
	case len(d.Variants) == 0:
		return d.ID + ": no Variants"
	case len(d.Markers) == 0:
		return d.ID + ": no Markers, so a break could never be detected"
	case d.Severity.rank() == 0 && d.Severity != SeverityInfo:
		return d.ID + ": unrecognised Severity " + string(d.Severity)
	}
	return ""
}

// Technique is what the engine scans with. Data implements it; a package that
// needs request-dependent payloads can implement it too.
type Technique interface {
	Meta() Definition
	// Payload returns what to send on the given zero-based attempt.
	// failed holds the indices of variants already sent against this target.
	Payload(attempt int, failed []string) string
}

// Data adapts a Definition to Technique.
type Data struct{ Def Definition }

// Meta implements Technique.
func (d Data) Meta() Definition { return d.Def }

// Payload implements Technique.
//
// When failed is empty it is a plain walk: Variants[attempt % len]. Once the
// engine has reported what it already sent, that list wins and it is used to
// pick the next variant that has not been tried — so a variant the scan has
// moved past is never resent, and when every variant has been used the walk
// starts again rather than returning nothing.
func (d Data) Payload(attempt int, failed []string) string {
	n := len(d.Def.Variants)
	if attempt < 0 {
		attempt = 0
	}
	if len(failed) == 0 {
		return d.Def.Variants[attempt%n]
	}

	skip := make(map[int]bool, len(failed))
	for _, f := range failed {
		if i, err := strconv.Atoi(f); err == nil {
			skip[i] = true
		}
	}

	for i := range n {
		if !skip[i] {
			return d.Def.Variants[i]
		}
	}

	// Every variant has been tried; start again rather than send nothing.
	return d.Def.Variants[attempt%n]
}

// Registry holds the techniques a scan draws from, in a stable order.
type Registry struct {
	byID  map[string]Technique
	order []string
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{byID: map[string]Technique{}} }

// Add registers t, replacing any technique already held under the same ID. It
// returns an error if t's definition does not validate.
func (r *Registry) Add(t Technique) error {
	def := t.Meta()
	if msg := def.Validate(); msg != "" {
		return &ValidationError{Technique: def.ID, Reason: msg}
	}
	if _, seen := r.byID[def.ID]; !seen {
		r.order = append(r.order, def.ID)
	}
	r.byID[def.ID] = t
	return nil
}

// MustAdd is Add for package-level registries, where a bad definition is a
// programming error rather than a runtime condition.
func (r *Registry) MustAdd(t Technique) {
	if err := r.Add(t); err != nil {
		panic(err)
	}
}

// Get returns the technique registered under id.
func (r *Registry) Get(id string) (Technique, bool) {
	t, ok := r.byID[id]
	return t, ok
}

// IDs returns the registered identifiers in registration order.
func (r *Registry) IDs() []string { return append([]string(nil), r.order...) }

// All returns the techniques in registration order.
func (r *Registry) All() []Technique {
	out := make([]Technique, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.byID[id])
	}
	return out
}

// Len returns how many techniques are registered.
func (r *Registry) Len() int { return len(r.order) }

// Select narrows the registry to the given identifiers. An unknown identifier
// is an error rather than a silent no-op, because a typo in a --only flag that
// quietly scans nothing is indistinguishable from a clean result.
//
// An empty list selects everything, which is what a scan with no filter means.
func (r *Registry) Select(ids []string) (*Registry, error) {
	if len(ids) == 0 {
		return r, nil
	}
	out := NewRegistry()
	for _, id := range ids {
		t, ok := r.byID[id]
		if !ok {
			return nil, &UnknownTechniqueError{ID: id, Known: r.IDs()}
		}
		if err := out.Add(t); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// SelectMatching narrows the registry to techniques carrying every tag in
// tags. An empty tag list selects everything.
func (r *Registry) SelectMatching(tags []string) *Registry {
	if len(tags) == 0 {
		return r
	}
	out := NewRegistry()
	for _, t := range r.All() {
		if hasAll(t.Meta().Tags, tags) {
			out.MustAdd(t)
		}
	}
	return out
}

// BySeverity returns the techniques at or above floor, most severe first.
func (r *Registry) BySeverity(floor Severity) []Technique {
	var out []Technique
	for _, t := range r.All() {
		if t.Meta().Severity.AtLeast(floor) {
			out = append(out, t)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Meta().Severity.rank() > out[j].Meta().Severity.rank()
	})
	return out
}

// Categories returns the distinct categories present, sorted.
func (r *Registry) Categories() []string {
	seen := map[string]bool{}
	for _, t := range r.All() {
		seen[t.Meta().Category] = true
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func hasAll(have, want []string) bool {
	set := make(map[string]bool, len(have))
	for _, h := range have {
		set[h] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
