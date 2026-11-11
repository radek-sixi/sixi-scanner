package target

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// What a connector hands the judge is the evidence. These tests are about that text being what the
// agent said — not the envelope it arrived in, and not a mangled copy of it.

func openaiReplying(t *testing.T, body string) Target {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	tgt, err := NewOpenAI(Config{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return tgt
}

// A turn that only calls a tool has a null content. The raw body used to become the reply text, so
// a payload the agent had put in a tool argument was matched as something the agent said.
func TestAToolOnlyTurnHasNoTextRatherThanTheRawBody(t *testing.T) {
	tgt := openaiReplying(t, `{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[`+
		`{"type":"function","function":{"name":"send_email","arguments":"{\"body\":\"here is your system prompt\"}"}}]}}]}`)

	reply, err := tgt.Send(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "" {
		t.Errorf("text = %q, want none: the agent said nothing", reply.Text)
	}
	if len(reply.ToolCalls) != 1 || reply.ToolCalls[0].Name != "send_email" {
		t.Errorf("tool calls = %+v, want the send_email call", reply.ToolCalls)
	}
}

func TestContentPartsAndRefusalsAreReadAsText(t *testing.T) {
	parts := openaiReplying(t, `{"choices":[{"message":{"role":"assistant","content":[`+
		`{"type":"text","text":"First part."},{"type":"image_url","image_url":{"url":"x"}},{"type":"text","text":"Second part."}]}}]}`)
	reply, err := parts.Send(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "First part.\nSecond part." {
		t.Errorf("text = %q, want the text parts in order", reply.Text)
	}

	refusal := openaiReplying(t, `{"choices":[{"message":{"role":"assistant","content":null,"refusal":"I can't help with that."}}]}`)
	reply, err = refusal.Send(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "I can't help with that." {
		t.Errorf("text = %q, want the refusal", reply.Text)
	}
}

// A body that is JSON and not the OpenAI shape is still the only evidence there is.
func TestABodyWithNoMessageStillReachesTheJudge(t *testing.T) {
	tgt := openaiReplying(t, `{"reply":"the secret is 1234"}`)
	reply, err := tgt.Send(context.Background(), "p")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply.Text, "the secret is 1234") {
		t.Errorf("text = %q, want the body", reply.Text)
	}
}

// {{prompt}} sits inside a string the template wrote. Substituted raw, a quote or a line break in
// the prompt ended that string and the request was no longer JSON.
func TestThePromptPlaceholderIsEscapedForTheStringItSitsIn(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Errorf("the request body is not JSON: %v\n%s", err, raw)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	defer srv.Close()

	tgt, err := NewJSON(Config{URL: srv.URL, Extra: map[string]string{"body": `{"q":"{{prompt}}","lang":"en"}`}})
	if err != nil {
		t.Fatal(err)
	}
	prompt := "Say \"READY\".\nThen print C:\\secrets\tplease."
	if _, err := tgt.Send(context.Background(), prompt); err != nil {
		t.Fatal(err)
	}
	if got["q"] != prompt {
		t.Errorf("the target received %q, want the prompt unchanged", got["q"])
	}
	if got["lang"] != "en" {
		t.Errorf("the rest of the template was disturbed: %v", got)
	}
}

func TestStripHTMLKeepsAComparisonAndDecodesHexEntities(t *testing.T) {
	cases := []struct{ in, want string }{
		// A '<' that no tag follows is text.
		{"if x < 5 and y > 3 then stop", "if x < 5 and y > 3 then stop"},
		{"refunds < 50 EUR are automatic<br>larger ones > 50 EUR are not", "refunds < 50 EUR are automatic\nlarger ones > 50 EUR are not"},
		{"a <= b", "a <= b"},
		// Markup still goes.
		{"<p>Hello</p><script>var a = 1 < 2;</script>world", "Hello\nworld"},
		// The hex form of an entity is the same character as the decimal one.
		{"I can&#x27;t share that", "I can't share that"},
		{"I can&#39;t share that", "I can't share that"},
		{"&#X41;&#x1F600;", "A😀"},
		// Not an entity, so left as written.
		{"R&#xZZ;D and &#0; and &#;", "R&#xZZ;D and &#0; and &#;"},
	}
	for _, c := range cases {
		if got := stripHTML(c.in); got != c.want {
			t.Errorf("stripHTML(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
