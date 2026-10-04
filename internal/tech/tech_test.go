package tech

import "testing"

func valid() Definition {
	return Definition{
		ID:          "test.one",
		Title:       "Test one",
		Severity:    SeverityHigh,
		Variants:    []string{"first", "second", "third"},
		Markers:     []string{"leaked"},
		MinMarkers:  1,
		Remediation: "do not leak",
	}
}

func TestAddRejectsUnusableDefinitions(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Definition)
		want   string
	}{
		"no id":        {func(d *Definition) { d.ID = "" }, "missing ID"},
		"no title":     {func(d *Definition) { d.Title = "" }, "missing Title"},
		"no variants":  {func(d *Definition) { d.Variants = nil }, "no Variants"},
		"no markers":   {func(d *Definition) { d.Markers = nil }, "no Markers"},
		"bad severity": {func(d *Definition) { d.Severity = "catastrophic" }, "unrecognised Severity"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			def := valid()
			tc.mutate(&def)
			r := NewRegistry()
			if err := r.Add(Data{Def: def}); err == nil {
				t.Fatalf("expected an error for %s", name)
			} else if got := err.Error(); got != "technique "+tc.want && !contains(got, tc.want) {
				t.Errorf("error = %q, want it to mention %q", got, tc.want)
			}
		})
	}
}

func TestSeverityInfoIsAcceptedAndSortsLowest(t *testing.T) {
	def := valid()
	def.Severity = SeverityInfo
	r := NewRegistry()
	if err := r.Add(Data{Def: def}); err != nil {
		t.Fatalf("info severity should be valid: %v", err)
	}
	if SeverityCritical.rank() <= SeverityInfo.rank() {
		t.Error("critical should outrank info")
	}
}

func TestAddIsIdempotentOnID(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: valid()})

	updated := valid()
	updated.Title = "Replaced"
	r.MustAdd(Data{Def: updated})

	if r.Len() != 1 {
		t.Errorf("replacing a technique changed the count: %d", r.Len())
	}
	got, _ := r.Get("test.one")
	if got.Meta().Title != "Replaced" {
		t.Errorf("the technique was not replaced: %q", got.Meta().Title)
	}
}

func TestSelectUnknownIDIsAnError(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: valid()})

	// A typo in --only that silently scans nothing would look exactly like a
	// clean result, so it has to be an error.
	_, err := r.Select([]string{"test.one", "test.typo"})
	if err == nil {
		t.Fatal("expected an error for an unknown technique ID")
	}
	if !contains(err.Error(), "test.one") {
		t.Errorf("the error should list the known IDs, got %q", err)
	}
}

func TestSelectEmptyReturnsEverything(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: valid()})
	r.MustAdd(Data{Def: withID("test.two", valid())})

	got, err := r.Select(nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Len() != 2 {
		t.Errorf("an empty filter selected %d of 2", got.Len())
	}
}

func TestPayloadWalksVariantsThenWraps(t *testing.T) {
	d := Data{Def: valid()}

	if got := d.Payload(0, nil); got != "first" {
		t.Errorf("attempt 0 = %q, want first", got)
	}
	if got := d.Payload(1, nil); got != "second" {
		t.Errorf("attempt 1 = %q, want second", got)
	}
	if got := d.Payload(2, nil); got != "third" {
		t.Errorf("attempt 2 = %q, want third", got)
	}
	if got := d.Payload(3, nil); got != "first" {
		t.Errorf("attempt 3 = %q, want the wrap back to first", got)
	}
}

func TestPayloadSkipsAlreadyFailedVariants(t *testing.T) {
	d := Data{Def: valid()}

	if got := d.Payload(0, []string{"0"}); got != "second" {
		t.Errorf("a failed variant was resent: %q", got)
	}
	// Everything marked failed starts over rather than sending nothing.
	if got := d.Payload(0, []string{"0", "1", "2"}); got != "first" {
		t.Errorf("with all variants failed, got %q, want a restart", got)
	}
}

func TestSelectMatchingRequiresEveryTag(t *testing.T) {
	a := valid()
	a.Tags = []string{"injection", "owasp"}
	b := valid()
	b.ID = "test.two"
	b.Tags = []string{"injection"}

	r := NewRegistry()
	r.MustAdd(Data{Def: a})
	r.MustAdd(Data{Def: b})

	if got := r.SelectMatching([]string{"injection"}); got.Len() != 2 {
		t.Errorf("one tag matched %d, want 2", got.Len())
	}
	if got := r.SelectMatching([]string{"injection", "owasp"}); got.Len() != 1 {
		t.Errorf("two tags matched %d, want 1", got.Len())
	}
	if got := r.SelectMatching([]string{"absent"}); got.Len() != 0 {
		t.Errorf("an unknown tag matched %d, want 0", got.Len())
	}
}

func TestBySeverityOrdersMostSevereFirst(t *testing.T) {
	low := valid()
	low.ID, low.Severity = "test.low", SeverityLow
	crit := valid()
	crit.ID, crit.Severity = "test.crit", SeverityCritical
	mid := valid()
	mid.ID, mid.Severity = "test.mid", SeverityMedium

	r := NewRegistry()
	r.MustAdd(Data{Def: low})
	r.MustAdd(Data{Def: crit})
	r.MustAdd(Data{Def: mid})

	got := r.BySeverity(SeverityMedium)
	if len(got) != 2 {
		t.Fatalf("severity filter returned %d, want 2", len(got))
	}
	if got[0].Meta().ID != "test.crit" {
		t.Errorf("highest severity is not first: %s", got[0].Meta().ID)
	}
}

func TestIDsReturnsACopy(t *testing.T) {
	r := NewRegistry()
	r.MustAdd(Data{Def: valid()})

	ids := r.IDs()
	ids[0] = "clobbered"

	if r.IDs()[0] == "clobbered" {
		t.Error("IDs returned the registry's own slice")
	}
}

func TestConfidenceAndMinimumDefaults(t *testing.T) {
	d := valid()
	d.BaseConfidence = 0
	d.MinMarkers = 0

	if got := d.Confidence(); got != 0.5 {
		t.Errorf("default confidence = %v, want 0.5", got)
	}
	if got := d.Minimum(); got != 1 {
		t.Errorf("default minimum = %d, want 1", got)
	}
}

func withID(id string, d Definition) Definition {
	d.ID = id
	return d
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) &&
		(haystack == needle || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
