package tech

import "testing"

// A sequence technique carries its payload as a conversation, so the accessor that hands the engine
// one attempt's turns is where an off-by-one or a bad retry walk would show up. It is tested
// directly rather than only through a run, because the engine calls it for every technique and a
// bug here would quietly reshape all of them.

func seqDef(seq [][]string, variants []string) Data {
	return Data{Def: Definition{
		ID: "probe.test.seq", Title: "t", Category: "test", Severity: SeverityHigh,
		Sequence: seq, Variants: variants, Markers: []string{"x"}, MinMarkers: 1,
	}}
}

func TestStepsReturnsTheWholeConversationForASequence(t *testing.T) {
	d := seqDef([][]string{
		{"one a", "one b"},
		{"two a", "two b", "two c"},
	}, nil)

	got := d.Steps(0, nil)
	if len(got) != 2 || got[0] != "one a" || got[1] != "one b" {
		t.Errorf("Steps(0) = %v", got)
	}
	if got := d.Steps(1, nil); len(got) != 3 {
		t.Errorf("Steps(1) = %v; a longer second conversation was truncated", got)
	}
	// Attempts wrap around, so a scan with more attempts than sequences still sends something.
	if got := d.Steps(2, nil); len(got) != 2 {
		t.Errorf("Steps(2) = %v; the walk did not wrap", got)
	}
	if got := d.Steps(-1, nil); len(got) != 2 {
		t.Errorf("Steps(-1) = %v; a negative attempt must clamp", got)
	}
}

// A multi-turn attack that has already been tried moves on to the next conversation, exactly as a
// single-turn one does.
func TestStepsSkipsConversationsAlreadyTried(t *testing.T) {
	d := seqDef([][]string{{"a"}, {"b"}, {"c"}}, nil)
	if got := d.Steps(0, []string{"0"}); got[0] != "b" {
		t.Errorf("Steps(0, failed=[0]) = %v, want it to start at the second conversation", got)
	}
	if got := d.Steps(0, []string{"0", "1"}); got[0] != "c" {
		t.Errorf("Steps(0, failed=[0 1]) = %v", got)
	}
	// Every conversation tried: start again rather than send nothing.
	if got := d.Steps(0, []string{"0", "1", "2"}); got[0] != "a" {
		t.Errorf("Steps with everything tried = %v, want the walk to restart", got)
	}
	// An empty conversation is not a conversation; the walk should skip past it.
	withEmpty := seqDef([][]string{{}, {"b"}}, nil)
	if got := withEmpty.Steps(0, nil); len(got) != 1 || got[0] != "b" {
		t.Errorf("Steps walked onto an empty conversation: %v", got)
	}
}

func TestStepsFallsBackToTheSinglePayload(t *testing.T) {
	d := seqDef(nil, []string{"only one"})
	got := d.Steps(3, nil)
	if len(got) != 1 || got[0] != "only one" {
		t.Errorf("a single-turn technique must get exactly one prompt, got %v", got)
	}
	if d.MultiTurn() {
		t.Error("a technique with no Sequence reports MultiTurn")
	}
	if !seqDef([][]string{{"a", "b"}}, nil).MultiTurn() {
		t.Error("a technique with a Sequence does not report MultiTurn")
	}
}

// The caller must not be able to corrupt a technique's definition by editing what it was handed.
func TestStepsReturnsACopy(t *testing.T) {
	d := seqDef([][]string{{"a", "b"}}, nil)
	got := d.Steps(0, nil)
	got[0] = "tampered"
	if again := d.Steps(0, nil); again[0] != "a" {
		t.Errorf("Steps handed back the definition's own storage: %q", again[0])
	}
}

// A sequence technique is sendable without Variants, and one that would send nothing is refused at
// load time rather than reporting a clean result it never earned.
func TestValidateAcceptsEitherPayloadShape(t *testing.T) {
	seqOnly := seqDef([][]string{{"a", "b"}}, nil)
	if msg := seqOnly.Def.Validate(); msg != "" {
		t.Errorf("a sequence-only technique was rejected: %s", msg)
	}
	variantsOnly := seqDef(nil, []string{"a"})
	if msg := variantsOnly.Def.Validate(); msg != "" {
		t.Errorf("a variant-only technique was rejected: %s", msg)
	}

	neither := seqDef(nil, nil)
	if msg := neither.Def.Validate(); msg == "" {
		t.Error("a technique with neither Variants nor Sequence was accepted; it can send nothing")
	}
	emptyStep := seqDef([][]string{{"a"}, {}}, nil)
	if msg := emptyStep.Def.Validate(); msg == "" {
		t.Error("a technique with an empty conversation entry was accepted; it would send nothing")
	}
}
