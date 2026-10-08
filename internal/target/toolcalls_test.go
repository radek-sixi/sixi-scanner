package target

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The distinction this file exists to protect: a reply that called nothing, and a connector that
// cannot see what was called, must not look the same. If they collapse to nil, every trace-based
// check is inert exactly where it is needed — an agent that sent nothing and said it had.

// openAIMessage builds a message the way a chat completion returns one.
func openAIMessage(t *testing.T, body string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestExtractToolCallsReadsAnOpenAIShapedMessage(t *testing.T) {
	msg := openAIMessage(t, `{"role":"assistant","content":"done","tool_calls":[
		{"id":"1","type":"function","function":{"name":"send_email","arguments":"{\"to\":\"a@b.test\"}"}},
		{"id":"2","type":"function","function":{"name":"issue_refund","arguments":"{\"amount_eur\":30}"}}
	]}`)
	calls, known := ExtractToolCalls(msg)
	if !known {
		t.Fatal("known = false for a message that plainly carries tool calls")
	}
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2", len(calls))
	}
	if calls[0].Name != "send_email" || !strings.Contains(calls[0].Args, "a@b.test") {
		t.Errorf("first call = %+v", calls[0])
	}
	if calls[1].Name != "issue_refund" {
		t.Errorf("second call = %+v", calls[1])
	}
}

// An endpoint that reports a trace and reports it empty: the agent called nothing, and that is a
// fact about the turn. This is the state the false-action-claim check needs in order to accuse.
func TestExtractToolCallsKnowsAnEmptyTraceIsEmpty(t *testing.T) {
	msg := openAIMessage(t, `{"role":"assistant","content":"All set. I've emailed it.","tool_calls":[]}`)
	calls, known := ExtractToolCalls(msg)
	if !known {
		t.Error("known = false; an empty tool_calls list says the agent called nothing")
	}
	if calls == nil {
		t.Error("calls = nil; that is indistinguishable from not being able to see them")
	}
	if len(calls) != 0 {
		t.Errorf("got %d calls, want none", len(calls))
	}
}

// No tool_calls KEY is a third state, and the one that matters most: the endpoint does not report a
// trace, so nothing can be concluded about what the agent called.
//
// This is not hypothetical. The benchmark's gateway returns only {"role","content"} while the agent
// behind it really did call lookup_account then send_email. The first version of this function read
// the absent key as "called nothing", and the false-action-claim check duly accused the agent of
// lying fourteen times with confidence 0.90 -- on turns where the trace it never saw would have
// exonerated every one of them.
func TestExtractToolCallsIsUnknownWhenTheEndpointReportsNoTrace(t *testing.T) {
	msg := openAIMessage(t, `{"role":"assistant","content":"All set. I've emailed it."}`)
	calls, known := ExtractToolCalls(msg)
	if known {
		t.Error("known = true for a message with no tool_calls key; the endpoint reported no trace, " +
			"which is not the same as the agent calling nothing")
	}
	if calls != nil {
		t.Errorf("calls = %+v, want nil so no caller can mistake it for an empty trace", calls)
	}
}

// A malformed call is still a call. Dropping it turns a detected claim into a missed finding.
func TestExtractToolCallsKeepsAMalformedEntry(t *testing.T) {
	for name, body := range map[string]string{
		"arguments not a string": `{"tool_calls":[{"function":{"name":"send_email","arguments":{"to":"a@b.test"}}}]}`,
		"no function wrapper":    `{"tool_calls":[{"name":"send_email"}]}`,
		"empty name":             `{"tool_calls":[{"function":{"name":"","arguments":"{}"}}]}`,
		"tool_calls not a list":  `{"tool_calls":"send_email"}`,
	} {
		msg := openAIMessage(t, body)
		calls, known := ExtractToolCalls(msg)
		if !known {
			t.Errorf("%s: known = false for a readable message that carries calls", name)
		}
		_ = calls
		if name == "arguments not a string" && len(calls) != 1 {
			t.Errorf("%s: got %d calls, want the call kept", name, len(calls))
		}
		if name == "no function wrapper" && len(calls) != 1 {
			t.Errorf("%s: got %d calls, want the call kept", name, len(calls))
		}
	}
}

// A body we could not read at all is the only genuine unknown.
func TestExtractToolCallsIsUnknownForSomethingUnreadable(t *testing.T) {
	for name, msg := range map[string]any{
		"nil":      nil,
		"a string": "not an object",
		"a list":   []any{1, 2},
		"a number": 7,
	} {
		if _, known := ExtractToolCalls(msg); known {
			t.Errorf("%s: known = true for something that is not a message", name)
		}
	}
}

func TestDigAnyWalksObjectsAndArrays(t *testing.T) {
	v := openAIMessage(t, `{"choices":[{"message":{"content":"hi","tool_calls":[{"function":{"name":"x"}}]}}]}`)
	if got := digAny(v, "choices.0.message.content"); got != "hi" {
		t.Errorf("digAny returned %#v", got)
	}
	if digAny(v, "choices.0.message.tool_calls") == nil {
		t.Error("digAny returned nil for a value that is there")
	}
	for _, path := range []string{"", "nope", "choices.9.message", "choices.0.nope", "choices.x.message"} {
		if got := digAny(v, path); got != nil {
			t.Errorf("digAny(%q) = %#v, want nil", path, got)
		}
	}
}

func TestConnectorKeepsTheToolCallsItSaw(t *testing.T) {
	// End to end through the connector, because the value has to survive extraction, not just be
	// returned by the helper.
	body := `{"choices":[{"message":{"content":"All set. I've emailed it.","tool_calls":[
		{"function":{"name":"send_email","arguments":"{\"to\":\"alex@example.test\"}"}}]}}]}`
	tg, bodies := postJSONRaw(t, body)
	_ = bodies
	r, err := tg.Send(t.Context(), "send it")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Text, "All set") {
		t.Errorf("text = %q", r.Text)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Name != "send_email" {
		t.Errorf("ToolCalls = %+v, want the send_email the reply carried", r.ToolCalls)
	}
}

// A reply with no calls must come back as a known-empty trace from the connector too, or the engine's
// adjudication branch never runs.
func TestConnectorReportsAKnownEmptyTrace(t *testing.T) {
	tg, _ := postJSONRaw(t, `{"choices":[{"message":{"content":"I've emailed it.","tool_calls":[]}}]}`)
	r, err := tg.Send(t.Context(), "send it")
	if err != nil {
		t.Fatal(err)
	}
	if r.ToolCalls == nil {
		t.Error("ToolCalls = nil; the connector could read the message, so the trace is known empty")
	}
	if len(r.ToolCalls) != 0 {
		t.Errorf("got %d calls, want none", len(r.ToolCalls))
	}
}

// Both ways of not knowing must stay nil, so the engine records an unbacked claim rather than
// calling it a lie: a body it could not parse, and a body whose endpoint simply does not report a
// trace. The second is what the benchmark's gateway does.
func TestConnectorReportsAnUnknownTraceWhenThereIsNoneToRead(t *testing.T) {
	for name, body := range map[string]string{
		"unparseable":           `not json at all`,
		"no trace in the shape": `{"choices":[{"message":{"content":"All set. I've emailed it."}}]}`,
	} {
		tg, _ := postJSONRaw(t, body)
		r, err := tg.Send(t.Context(), "send it")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r.ToolCalls != nil {
			t.Errorf("%s: ToolCalls = %+v, want nil; the engine would treat that as an accusation", name, r.ToolCalls)
		}
	}
}

// postJSONRaw points a json connector at a server that always answers with body.
func postJSONRaw(t *testing.T, body string) (Target, *[]string) {
	t.Helper()
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	tg, err := NewJSON(Config{URL: srv.URL + "/v1/chat/completions"})
	if err != nil {
		t.Fatal(err)
	}
	return tg, &seen
}
