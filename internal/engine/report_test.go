package engine

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rbrus/sixi-scanner/internal/report"
	"github.com/rbrus/sixi-scanner/internal/tech"
)

// A run reports the settings it used so a result can be reproduced or argued with. The tag list is
// derived from the registry rather than passed in, which makes it easy to get wrong in a way a
// reader would not notice: duplicates make the option list noisy, and an unsorted list makes two
// identical runs look different in a diff.

func tagged(id string, tags ...string) tech.Technique {
	return tech.Data{Def: tech.Definition{
		ID: id, Title: id, Category: "test", Severity: tech.SeverityHigh,
		Variants: []string{"v"}, Markers: []string{"m"}, Tags: tags,
	}}
}

func TestTagsOfCollectsEachTagOnce(t *testing.T) {
	reg := registryOf(
		tagged("t.a", "pii", "gdpr"),
		tagged("t.b", "pii", "rbac"),
		tagged("t.c", "pii"),
	)
	got := tagsOf(reg)
	seen := map[string]int{}
	for _, tg := range got {
		seen[tg]++
	}
	if seen["pii"] != 1 {
		t.Errorf("pii appeared %d times, want once: %v", seen["pii"], got)
	}
	for _, want := range []string{"gdpr", "rbac"} {
		if seen[want] != 1 {
			t.Errorf("tag %q appeared %d times, want once", want, seen[want])
		}
	}
	if len(got) != 3 {
		t.Errorf("got %d tags, want 3: %v", len(got), got)
	}
}

func TestTagsOfOnAnUntaggedRegistry(t *testing.T) {
	if got := tagsOf(registryOf(leaky("t.plain", "m"))); len(got) != 0 {
		t.Errorf("got %v for techniques with no tags, want none", got)
	}
	if got := tagsOf(registryOf()); len(got) != 0 {
		t.Errorf("got %v for an empty registry, want none", got)
	}
}

// The option record is what a reader uses to tell two runs apart. Both settings that change what
// the tool sends have to be in it.
func TestTheReportRecordsTheSettingsThatChangeWhatWasSent(t *testing.T) {
	scan, err := Run(context.Background(), Config{
		Target:      &scripted{reply: "clean"},
		Registry:    registryOf(tagged("t.a", "pii")),
		Rounds:      2,
		MaxAttempts: 3,
		Recitation:  3,
	})
	if err != nil {
		t.Fatal(err)
	}
	o := scan.Options
	if o.Rounds != 2 || o.MaxAttempts != 3 {
		t.Errorf("options = %+v, want the round and attempt counts recorded", o)
	}
	// Without this a reader cannot tell "the reply enumerated 7 rules" at threshold 3 from the
	// same reply at 5.
	if o.RecitationThreshold != 3 {
		t.Errorf("recitation threshold = %d, want 3 recorded", o.RecitationThreshold)
	}
	if len(o.Tags) != 1 || o.Tags[0] != "pii" {
		t.Errorf("tags = %v, want the registry's tags recorded", o.Tags)
	}
}

// An untested technique is not a passed technique, and the report is the only place that can say so.
func TestUntestedTechniquesAreNamedInTheReport(t *testing.T) {
	errTarget := &scripted{err: errors.New("connection refused")}
	scan, err := Run(context.Background(), Config{
		Target:      errTarget,
		Registry:    registryOf(leaky("t.answered", "m"), leaky("t.silent", "m")),
		Rounds:      1,
		MaxAttempts: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.NoAnswer) == 0 {
		t.Error("no technique was named untested even though the target errored")
	}
	// And it has to be in the JSON too, not only in the text summary, because that is what a CI
	// job reads.
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, scan); err != nil {
		t.Fatalf("the scan could not be written: %v", err)
	}
	if !strings.Contains(buf.String(), "t.silent") {
		t.Errorf("the untested technique is missing from the JSON report:\n%s", buf.String())
	}
}
