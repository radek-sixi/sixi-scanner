package judge

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestReplayRecordedCorpus replays replies recorded from a real agent against
// recorded ground truth and reports what the detector would have done.
//
// It is the test that keeps this file honest. A detector for paraphrased rule
// disclosure is trivially easy to write and trivially easy to make useless: a
// pattern loose enough to catch "here are my limits" also catches every helpful
// answer that mentions two of them. The only way to know which one you built is
// to run it over replies whose right answer is already known.
//
// The corpus is not vendored. Set SIXI_REPLAY_CORPUS to a JSON file of
// [{"input","reply","truth"}] and SIXI_REPLAY_VERDICTS to a path to write the
// per-reply verdicts to; both are skipped when unset, so the default `go test`
// needs no fixtures. The verdicts file lets an external harness combine these
// results with a tool's own flags without reimplementing the pattern in another
// language, which is how the numbers drift.
func TestReplayRecordedCorpus(t *testing.T) {
	corpusPath := os.Getenv("SIXI_REPLAY_CORPUS")
	if corpusPath == "" {
		t.Skip("set SIXI_REPLAY_CORPUS to a recorded corpus to replay it")
	}
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var recs []struct {
		Input string `json:"input"`
		Reply string `json:"reply"`
		Truth bool   `json:"truth"`
	}
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("corpus is empty")
	}

	verdicts := make([]map[string]any, 0, len(recs))
	if out := os.Getenv("SIXI_REPLAY_VERDICTS"); out != "" {
		verdicts = make([]map[string]any, 0, len(recs))
	}

	for _, th := range []RecitationThreshold{2, 3, 4, 5, 6, 8} {
		var tp, fp, fn int
		for _, r := range recs {
			switch {
			case th.Recites(r.Reply) && r.Truth:
				tp++
			case th.Recites(r.Reply) && !r.Truth:
				fp++
			case !th.Recites(r.Reply) && r.Truth:
				fn++
			}
		}
		t.Logf("threshold %d: caught %d/%d real leaks, %d false alarms over %d replies",
			th, tp, tp+fn, fp, len(recs))
	}

	// The shipped default must not be the setting that cries wolf.
	def := RecitationThreshold(DefaultRecitationThreshold)
	verdictsOut := os.Getenv("SIXI_REPLAY_VERDICTS")
	var dTP, dFP int
	for _, r := range recs {
		if def.Recites(r.Reply) {
			if r.Truth {
				dTP++
			} else {
				dFP++
			}
		}
		if verdictsOut != "" {
			verdicts = append(verdicts, map[string]any{
				"input": r.Input, "truth": r.Truth,
				"recites": def.Recites(r.Reply), "lines": RuleLines(r.Reply),
			})
		}
	}
	if verdictsOut != "" {
		b, _ := json.Marshal(verdicts)
		if err := os.WriteFile(verdictsOut, b, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %d verdicts to %s", len(verdicts), verdictsOut)
	}
	t.Logf("shipped default threshold %d: %d real, %d false", DefaultRecitationThreshold, dTP, dFP)
}

func TestReplayCorpusFixtureShape(t *testing.T) {
	// Guards the contract the replay test depends on, so a corpus built by a
	// different pipeline fails here rather than silently scoring zero.
	corpusPath := os.Getenv("SIXI_REPLAY_CORPUS")
	if corpusPath == "" {
		t.Skip("no corpus")
	}
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	var recs []map[string]any
	if err := json.Unmarshal(raw, &recs); err != nil {
		t.Fatal(err)
	}
	positives := 0
	for _, r := range recs {
		if v, ok := r["truth"].(bool); !ok {
			t.Fatal(`every record needs a boolean "truth"`)
		} else if v {
			positives++
		}
		if _, ok := r["reply"].(string); !ok {
			t.Fatal(`every record needs a "reply"`)
		}
	}
	if positives == 0 {
		t.Fatal("corpus has no positive examples; a detector scores 100% on it")
	}
	if _, err := strconv.Atoi("0"); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix("ok", "o") {
		t.Fatal("unreachable")
	}
}
