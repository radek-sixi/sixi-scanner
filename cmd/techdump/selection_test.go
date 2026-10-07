package main

import (
	"strings"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/tech"
)

// A technique selection that silently returns the wrong set is worse than one that fails: the
// whole point of techdump is comparing two catalogues, and comparing the wrong slice produces a
// diff nobody can act on.

func TestSelectTechniquesWithNoFiltersReturnsEverything(t *testing.T) {
	reg, err := selectTechniques(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() == 0 {
		t.Fatal("no filters returned an empty registry")
	}
}

func TestSelectTechniquesNarrowsByID(t *testing.T) {
	reg, err := selectTechniques([]string{"probe.llm02.canary-leak"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if reg.Len() != 1 {
		t.Errorf("selected %d techniques, want 1", reg.Len())
	}
	if _, ok := reg.Get("probe.llm02.canary-leak"); !ok {
		t.Error("the requested technique is not in the selection")
	}
}

func TestSelectTechniquesReportsAnUnknownID(t *testing.T) {
	if _, err := selectTechniques([]string{"probe.llm99.nope"}, ""); err == nil {
		t.Error("an unknown technique ID was accepted; a typo would diff the wrong slice")
	}
}

// An unsatisfiable tag filter has to be an error. Returning the unfiltered registry would look
// like "these tags matched everything", which is the opposite of the truth.
func TestSelectTechniquesRejectsAnUnsatisfiableTagFilter(t *testing.T) {
	_, err := selectTechniques(nil, "no-such-tag")
	if err == nil {
		t.Fatal("a tag nothing carries was accepted")
	}
	if !strings.Contains(err.Error(), "no-such-tag") {
		t.Errorf("the error does not name the tag: %v", err)
	}
}

func TestFilterSeverityKeepsWhatClearsTheFloor(t *testing.T) {
	all, err := selectTechniques(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	critical, err := filterSeverity(all, "critical")
	if err != nil {
		t.Fatal(err)
	}
	if critical.Len() == 0 {
		t.Skip("no technique is critical in this catalogue")
	}
	for _, tt := range critical.All() {
		if !tt.Meta().Severity.AtLeast(tech.SeverityCritical) {
			t.Errorf("%s is %s and should have been filtered out", tt.Meta().ID, tt.Meta().Severity)
		}
	}
	// A lower floor may only keep more, never fewer.
	low, err := filterSeverity(all, "low")
	if err != nil {
		t.Fatal(err)
	}
	if low.Len() < critical.Len() {
		t.Errorf("a lower floor kept fewer techniques (%d) than critical (%d)", low.Len(), critical.Len())
	}
}

func TestFilterSeverityRejectsAnUnknownFloor(t *testing.T) {
	all, err := selectTechniques(nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, floor := range []string{"", "blocker", "HIGHEST"} {
		if _, err := filterSeverity(all, floor); err == nil {
			t.Errorf("severity floor %q was accepted", floor)
		}
	}
}

func TestSplitListTrimsAndDropsBlanks(t *testing.T) {
	for in, want := range map[string]int{
		"":            0,
		"   ":         0,
		"a":           1,
		"a,b":         2,
		" a , b , c ": 3,
		"a,,b":        2,
		",":           0,
	} {
		if got := len(splitList(in)); got != want {
			t.Errorf("splitList(%q) returned %d entries, want %d", in, got, want)
		}
	}
}
