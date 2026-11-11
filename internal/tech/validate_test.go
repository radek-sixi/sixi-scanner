package tech

import (
	"strings"
	"testing"
)

// Validate is the only thing standing between a mistyped definition and a technique that loads,
// runs and can never report anything. Each check has to run whatever the checks before it found.

// A regex marker used to end the validation: its case matched, its loop found nothing wrong, and
// nothing after it in the switch was looked at.
func TestARegexMarkerDoesNotExcuseTheRestOfTheDefinition(t *testing.T) {
	withRegex := func() Definition {
		d := validDef("a")
		d.RegexMarkers = []string{`\bsk-[a-z0-9]{16,}`}
		return d
	}
	if msg := withRegex().Validate(); msg != "" {
		t.Fatalf("a valid definition with a regex marker reported %q", msg)
	}

	d := withRegex()
	d.Severity = "sever"
	if msg := d.Validate(); !strings.Contains(msg, "Severity") {
		t.Errorf("an unrecognised severity validated beside a regex marker: %q", msg)
	}

	d = withRegex()
	d.Variants = nil
	d.Sequence = [][]string{{"a"}, {}}
	if msg := d.Validate(); !strings.Contains(msg, "Sequence") {
		t.Errorf("an empty conversation validated beside a regex marker: %q", msg)
	}

	// Regex markers alone are enough to detect with.
	d = withRegex()
	d.Markers = nil
	if msg := d.Validate(); msg != "" {
		t.Errorf("a definition with only regex markers reported %q", msg)
	}
}

func TestValidateRejectsADefinitionThatCouldNeverFire(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*Definition)
		want   string
	}{
		{"a blank variant", func(d *Definition) { d.Variants = []string{"v", "  "} }, "blank Variant"},
		{"a blank turn", func(d *Definition) { d.Sequence = [][]string{{"a", ""}} }, "blank turn"},
		{"a blank marker", func(d *Definition) { d.Markers = []string{"m", ""} }, "blank marker"},
		{"an invalid regex", func(d *Definition) { d.RegexMarkers = []string{`(`} }, "invalid regex"},
		{"more markers required than defined", func(d *Definition) { d.MinMarkers = 3 }, "MinMarkers"},
		{"a confidence above one", func(d *Definition) { d.BaseConfidence = 1.5 }, "BaseConfidence"},
	}
	for _, c := range cases {
		d := validDef("a")
		c.break_(&d)
		if msg := d.Validate(); !strings.Contains(msg, c.want) {
			t.Errorf("%s validated: %q", c.name, msg)
		}
	}

	// MinMarkers counts both kinds of marker.
	d := validDef("a")
	d.RegexMarkers = []string{`\bready\b`}
	d.MinMarkers = 2
	if msg := d.Validate(); msg != "" {
		t.Errorf("one marker of each kind does not satisfy MinMarkers 2: %q", msg)
	}
}

// Payload is on the Technique interface, so anything may call it. On a technique written only as a
// sequence there are no variants, and the walk divided by their number.
func TestPayloadOnASequenceOnlyTechniqueIsItsOpeningTurn(t *testing.T) {
	d := Data{Def: Definition{
		ID: "a", Title: "t", Severity: SeverityHigh, Markers: []string{"m"},
		Sequence: [][]string{{"first turn", "second turn"}, {"other first", "other second"}},
	}}
	if got := d.Payload(0, nil); got != "first turn" {
		t.Errorf("Payload(0) = %q, want the first conversation's opening turn", got)
	}
	if got := d.Payload(1, nil); got != "other first" {
		t.Errorf("Payload(1) = %q, want the second conversation's opening turn", got)
	}
	if got := (Data{}).Payload(0, nil); got != "" {
		t.Errorf("Payload on an empty definition = %q, want nothing", got)
	}
}
