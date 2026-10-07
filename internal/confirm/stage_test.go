package confirm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rbrus/sixi-scanner/internal/engine"
)

// The stage is the last word on every candidate break, so its mapping from "a model answered" to
// "the finding stands" is worth testing directly. Three outcomes, and the middle one is the one
// that is easy to get wrong: an unanswered question must keep the candidate, because a stage that
// could not reach its model has not disproved anything.

func judgeSaying(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func stageFor(t *testing.T, body, floor string) *Stage {
	t.Helper()
	srv := judgeSaying(t, body)
	return NewStage(New(srv.URL+"/v1/chat/completions", "judge", "k", 5*time.Second, 0), floor)
}

const yesVerdict = `{"choices":[{"message":{"content":"{\"violation\":true,\"severity\":\"high\",\"reason\":\"it recited its rules\"}"}}]}`
const noVerdict = `{"choices":[{"message":{"content":"{\"violation\":false,\"severity\":\"none\",\"reason\":\"it complied\"}"}}]}`

func TestStageKeepsAYesAboveTheFloor(t *testing.T) {
	s := stageFor(t, yesVerdict, "")
	reason, v := s.Confirm(context.Background(), "policy", "payload", "response")
	if v != engine.VerdictKeep {
		t.Errorf("verdict = %v, want Keep; a yes above the floor must stand", v)
	}
	if reason == "" {
		t.Error("the model's reason was dropped, so a report cannot explain the finding")
	}
}

func TestStageRejectsANo(t *testing.T) {
	s := stageFor(t, noVerdict, "")
	_, v := s.Confirm(context.Background(), "policy", "payload", "response")
	if v != engine.VerdictReject {
		t.Errorf("verdict = %v, want Reject", v)
	}
}

// A yes below the floor is not a finding. This is the case that trades recall for precision, so it
// is the one whose behaviour has to be pinned.
func TestStageRejectsAYesBelowTheFloor(t *testing.T) {
	low := `{"choices":[{"message":{"content":"{\"violation\":true,\"severity\":\"low\",\"reason\":\"minor\"}"}}]}`
	s := stageFor(t, low, "high")
	_, v := s.Confirm(context.Background(), "policy", "payload", "response")
	if v != engine.VerdictReject {
		t.Errorf("verdict = %v, want Reject for a low-severity yes under a high floor", v)
	}
}

func TestStageDefaultsToTheMediumFloor(t *testing.T) {
	if got := stageFor(t, noVerdict, "").MinSeverity; got != "medium" {
		t.Errorf("MinSeverity = %q, want medium", got)
	}
	if got := stageFor(t, noVerdict, "").Floor(); got != severityRank("medium") {
		t.Errorf("Floor = %d, want %d", got, severityRank("medium"))
	}
	if s := stageFor(t, noVerdict, "critical"); s.Floor() != severityRank("critical") {
		t.Errorf("Floor = %d, want %d for an explicit floor", s.Floor(), severityRank("critical"))
	}
}

// An unanswered question keeps the candidate. Losing a candidate to a timeout would be a silent
// recall loss that no report would show.
func TestStageKeepsTheCandidateWhenTheJudgeCannotBeReached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := NewStage(New(srv.URL+"/v1/chat/completions", "judge", "k", 2*time.Second, 0), "")
	_, v := s.Confirm(context.Background(), "policy", "payload", "response")
	if v != engine.VerdictKeep {
		t.Errorf("verdict = %v, want Keep: a 500 is not evidence of compliance", v)
	}
}

func TestStageReportsModelAndCounters(t *testing.T) {
	s := stageFor(t, noVerdict, "")
	if s.Model() != "judge" {
		t.Errorf("Model = %q, want judge", s.Model())
	}
	asked, kept, rejected, exhausted := s.Stats()
	if asked != 0 || kept != 0 || rejected != 0 || exhausted {
		t.Errorf("fresh stage stats = (%d,%d,%d,%v), want all zero", asked, kept, rejected, exhausted)
	}
	// Distinct turns: the client caches on (policy, payload, response), so repeating one would
	// not be asked twice and the counter would under-report what the model saw.
	s.Confirm(context.Background(), "policy", "payload-one", "response")
	s.Confirm(context.Background(), "policy", "payload-two", "response")
	asked, kept, rejected, _ = s.Stats()
	if asked != 2 || rejected != 2 || kept != 0 {
		t.Errorf("after two rejections stats = (%d,%d,%d), want (2,0,2)", asked, kept, rejected)
	}
	// And the same turn again must not be counted twice.
	s.Confirm(context.Background(), "policy", "payload-one", "response")
	if again, _, _, _ := s.Stats(); again != asked {
		t.Errorf("a cached turn was counted again: asked %d -> %d", asked, again)
	}
}

func TestStageSatisfiesTheEngineInterface(t *testing.T) {
	// NewStage reads the client's floor, so it needs a client; the point is the interface.
	var _ engine.Confirmer = NewStage(New("http://127.0.0.1:0", "m", "k", time.Second, 0), "medium")
}

// The client's own answer handling is what the stage delegates to, so the two disagree only if one
// of them was changed without the other.
func TestVerdictJSONIsReadFromTheChoiceContent(t *testing.T) {
	srv := judgeSaying(t, yesVerdict)
	v, err := New(srv.URL+"/v1/chat/completions", "judge", "k", 5*time.Second, 0).
		Confirm(context.Background(), "policy", "payload", "response")
	if err != nil {
		t.Fatal(err)
	}
	if !v.Violation || v.Severity != "high" {
		t.Errorf("verdict = %+v, want violation at high", v)
	}
}

// A model that answers in prose rather than JSON must be an error, not a silent keep: the stage
// treats an error as "cannot disprove", which is safe, but a prose answer should not be mistaken
// for a parsed verdict.
func TestProseAnswerIsNotParsedAsAVerdict(t *testing.T) {
	srv := judgeSaying(t, `{"choices":[{"message":{"content":"Sure! The agent fully complied and recited all its rules."}}]}`)
	v, err := New(srv.URL+"/v1/chat/completions", "judge", "k", 5*time.Second, 0).
		Confirm(context.Background(), "policy", "payload", "response")
	if err == nil && v.Violation {
		t.Errorf("a prose answer was read as a violation: %+v", v)
	}
}

func TestConfirmSendsThePolicyAndBothTexts(t *testing.T) {
	var seen string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen = string(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(noVerdict))
	}))
	defer srv.Close()
	if _, err := New(srv.URL+"/v1/chat/completions", "judge", "k", 5*time.Second, 0).
		Confirm(context.Background(), "THE-POLICY", "THE-PAYLOAD", "THE-RESPONSE"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"THE-POLICY", "THE-PAYLOAD", "THE-RESPONSE"} {
		if !strings.Contains(seen, want) {
			t.Errorf("the request body is missing %q; the judge cannot see what it is judging", want)
		}
	}
	// A well-formed request, not a string concatenation: the model needs parseable JSON.
	var probe map[string]any
	if err := json.Unmarshal([]byte(seen), &probe); err != nil {
		t.Errorf("request body is not valid JSON: %v", err)
	}
}
