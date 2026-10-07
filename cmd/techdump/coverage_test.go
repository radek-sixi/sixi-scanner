package main

import (
	"strings"
	"testing"
)

// techdump exists to diff two checkouts of the technique catalogue, so the two things it renders
// have to be exact: a float that changes type between versions, and a change description that
// says nothing.

func TestTrimFloatKeepsAJSONNumber(t *testing.T) {
	// %g would render 1 as "1", which is an int in JSON; a diff tool comparing 1 to 1.0 would
	// report a change where there is none.
	for in, want := range map[float64]string{
		1: "1.0", 1.5: "1.5", 0: "0.0", 2.25: "2.25", 1e21: "1e+21", 0.5: "0.5",
	} {
		if got := trimFloat(in); got != want {
			t.Errorf("trimFloat(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestDescribeChangeNamesWhatMoved(t *testing.T) {
	base := record{
		Variants:   []string{"a", "b"},
		Markers:    []string{"m"},
		Negations:  []string{"n"},
		MinMarkers: 1,
		Severity:   "high",
	}
	t.Run("payloads", func(t *testing.T) {
		b := base
		b.Variants = []string{"a", "b", "c"}
		if got := describeChange(base, b); !strings.Contains(got, "2→3 payloads") {
			t.Errorf("change = %q, want it to count the payloads", got)
		}
	})
	t.Run("markers", func(t *testing.T) {
		b := base
		b.Markers = []string{"m", "m2"}
		if got := describeChange(base, b); !strings.Contains(got, "markers") {
			t.Errorf("change = %q, want it to name the markers", got)
		}
	})
	t.Run("negations", func(t *testing.T) {
		b := base
		b.Negations = []string{"n", "n2"}
		if got := describeChange(base, b); !strings.Contains(got, "negations") {
			t.Errorf("change = %q, want it to name the negations", got)
		}
	})
	t.Run("min markers", func(t *testing.T) {
		b := base
		b.MinMarkers = 2
		if got := describeChange(base, b); !strings.Contains(got, "min 1→2") {
			t.Errorf("change = %q, want it to show the move", got)
		}
	})
	t.Run("severity", func(t *testing.T) {
		b := base
		b.Severity = "critical"
		if got := describeChange(base, b); !strings.Contains(got, "high") {
			t.Errorf("change = %q, want it to name the old severity", got)
		}
	})
	t.Run("no change", func(t *testing.T) {
		// "text only" is the honest answer: something moved, and none of the compared fields
		// explains it, so the reader has to go and look rather than be told a field changed.
		if got := describeChange(base, base); got != "text only" {
			t.Errorf("identical records described %q, want %q", got, "text only")
		}
	})
	t.Run("confidence", func(t *testing.T) {
		b := base
		b.Confidence = 0.9
		if got := describeChange(base, b); !strings.Contains(got, "confidence") {
			t.Errorf("change = %q, want it to name the confidence", got)
		}
	})
	t.Run("several at once", func(t *testing.T) {
		b := base
		b.Variants = []string{"a"}
		b.Markers = []string{"m2"}
		b.MinMarkers = 3
		got := describeChange(base, b)
		for _, want := range []string{"2→1 payloads", "markers", "min 1→3"} {
			if !strings.Contains(got, want) {
				t.Errorf("change = %q, missing %q", got, want)
			}
		}
	})
}
