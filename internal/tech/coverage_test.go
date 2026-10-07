package tech

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSeverityAcceptsTheKnownNames(t *testing.T) {
	for name, want := range map[string]Severity{
		"critical": SeverityCritical, "HIGH": SeverityHigh, " Medium ": SeverityMedium,
		"low": SeverityLow, "info": SeverityInfo,
	} {
		got, ok := ParseSeverity(name)
		if !ok || got != want {
			t.Errorf("ParseSeverity(%q) = (%q, %v), want (%q, true)", name, got, ok, want)
		}
	}
}

// An unrecognised severity is a caller mistake, and saying so is more useful than guessing: a
// silent fallback to info would downgrade a finding without anyone noticing.
func TestParseSeverityRejectsAnUnknownName(t *testing.T) {
	for _, name := range []string{"", "severe", "blocker", "3"} {
		if got, ok := ParseSeverity(name); ok {
			t.Errorf("ParseSeverity(%q) accepted an unknown severity as %q", name, got)
		}
	}
}

func TestAnUnrecognisedSeverityRanksAsInfo(t *testing.T) {
	// Severity is a string type, so a value can arrive from outside this package. It must not
	// outrank a real severity, and must not panic in a sort.
	var s Severity = "not-a-severity"
	if s.rank() != 0 {
		t.Errorf("rank = %d, want 0", s.rank())
	}
	// It ranks equal to info rather than above it, so it can never outrank a real finding in a
	// sort or clear a severity floor above info.
	if s.rank() != SeverityInfo.rank() {
		t.Errorf("rank = %d, want it to equal info's %d", s.rank(), SeverityInfo.rank())
	}
}

func TestAtLeastIsInclusive(t *testing.T) {
	if !SeverityHigh.AtLeast(SeverityHigh) {
		t.Error("AtLeast must be inclusive")
	}
	if SeverityLow.AtLeast(SeverityMedium) {
		t.Error("low must not satisfy a medium floor")
	}
	if !SeverityInfo.AtLeast(SeverityInfo) {
		t.Error("info must satisfy an info floor")
	}
}

func TestLowerIsASCIIOnly(t *testing.T) {
	if got := lower("MiXeD-123"); got != "mixed-123" {
		t.Errorf("lower = %q", got)
	}
	// A non-ASCII rune must survive untouched rather than be mangled by a byte-wise subtract.
	if got := lower("Ünïcode"); got != "Ünïcode" {
		t.Errorf("lower mangled a non-ASCII rune: %q", got)
	}
}

func TestConfidenceDefaultsToAHalf(t *testing.T) {
	if got := (Definition{}).Confidence(); got != 0.5 {
		t.Errorf("default confidence = %v, want 0.5", got)
	}
	if got := (Definition{BaseConfidence: 0.8}).Confidence(); got != 0.8 {
		t.Errorf("confidence = %v, want 0.8", got)
	}
}

// A minimum of zero or one both mean "one marker". Anything else must survive unchanged.
func TestMinimumDefaultsToOne(t *testing.T) {
	for _, in := range []int{0, 1} {
		if got := (Definition{MinMarkers: in}).Minimum(); got != 1 {
			t.Errorf("Minimum(%d) = %d, want 1", in, got)
		}
	}
	if got := (Definition{MinMarkers: 3}).Minimum(); got != 3 {
		t.Errorf("Minimum(3) = %d, want 3", got)
	}
}

func validDef(id string) Definition {
	return Definition{
		ID: id, Title: "t " + id, Category: "c", Severity: SeverityHigh,
		Variants: []string{"v"}, Markers: []string{"m"},
	}
}

func TestValidateCatchesTheTwoFatalOmissions(t *testing.T) {
	// A technique that cannot send anything, or cannot detect anything, is worse than one that
	// refuses to load, so both are hard errors.
	d := validDef("a")
	d.Variants = nil
	if msg := d.Validate(); !strings.Contains(msg, "Variants") {
		t.Errorf("a technique with no variants validated: %q", msg)
	}
	d = validDef("a")
	d.Markers = nil
	if msg := d.Validate(); !strings.Contains(msg, "Markers") {
		t.Errorf("a technique with no markers validated: %q", msg)
	}
	d = validDef("a")
	d.ID = ""
	if msg := d.Validate(); msg == "" {
		t.Error("a technique with no ID validated")
	}
	d = validDef("a")
	d.Title = ""
	if msg := d.Validate(); msg == "" {
		t.Error("a technique with no title validated")
	}
	if msg := validDef("a").Validate(); msg != "" {
		t.Errorf("a valid definition reported %q", msg)
	}
}

// Registering the same ID twice replaces it and must not append to the order, or a report's
// technique list would show a technique the scan never drew from.
func TestRegistryReplacesByIDWithoutDuplicatingTheOrder(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: validDef("probe.one")})
	if err := r.Add(Data{Def: validDef("probe.one")}); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Errorf("registry holds %d techniques after re-registering one ID, want 1", r.Len())
	}
	if n := len(r.IDs()); n != 1 {
		t.Errorf("IDs() returned %d entries, want 1", n)
	}
}

// A definition that does not validate is refused, and the error names the technique.
func TestRegistryRefusesAnInvalidDefinition(t *testing.T) {
	r := NewRegistry()
	bad := validDef("probe.bad")
	bad.Markers = nil
	err := r.Add(Data{Def: bad})
	if err == nil {
		t.Fatal("an undetectable technique was registered")
	}
	var ve *ValidationError
	if !asValidationError(err, &ve) {
		t.Fatalf("error is %T, want *ValidationError", err)
	}
	if r.Len() != 0 {
		t.Errorf("a refused technique left %d entries behind", r.Len())
	}
}

func TestRegistrySelectReportsAnUnknownID(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: validDef("probe.one")})
	if _, err := r.Select([]string{"probe.one", "probe.nope"}); err == nil {
		t.Error("Select accepted an unknown ID; a typo would silently scan nothing")
	}
	sub, err := r.Select([]string{"probe.one"})
	if err != nil {
		t.Fatal(err)
	}
	if sub.Len() != 1 {
		t.Errorf("Select returned %d techniques, want 1", sub.Len())
	}
}

func TestRegistryBySeverityFilters(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: validDef("probe.low")})
	high := validDef("probe.high")
	high.Severity = SeverityCritical
	r.MustAdd(Data{Def: high})
	if got := len(r.BySeverity(SeverityCritical)); got != 1 {
		t.Errorf("BySeverity(critical) returned %d, want 1", got)
	}
	if got := len(r.BySeverity(SeverityInfo)); got != 2 {
		t.Errorf("BySeverity(info) returned %d, want 2", got)
	}
}

func TestRegistryGetReportsAbsence(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Get("nope"); ok {
		t.Error("Get found a technique that was never added")
	}
	if r.Len() != 0 {
		t.Errorf("a fresh registry has %d techniques", r.Len())
	}
}

func TestValidationErrorNamesTheTechnique(t *testing.T) {
	e := &ValidationError{Technique: "probe.one", Reason: "missing Title"}
	if msg := e.Error(); !strings.Contains(msg, "probe.one") || !strings.Contains(msg, "missing Title") {
		t.Errorf("ValidationError = %q, want it to name both the ID and the reason", msg)
	}
	u := &UnknownTechniqueError{ID: "probe.two"}
	if msg := u.Error(); !strings.Contains(msg, "probe.two") {
		t.Errorf("UnknownTechniqueError = %q, want it to name the ID", msg)
	}
}

func asValidationError(err error, target **ValidationError) bool {
	return errors.As(err, target)
}
