package target

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The JSON connector is how most callers point the scanner at their own agent, so its two
// judgements — which part of the reply is the text, and what the request body looks like — are
// worth pinning. Both were once wrong in ways a user would only see as an empty report.

func postJSON(t *testing.T, reply string) (Target, *[]string) {
	t.Helper()
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		bodies = append(bodies, string(b))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	tg, err := NewJSON(Config{URL: srv.URL + "/v1/chat/completions", Extra: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	return tg, &bodies
}

func TestJSONReadsTheDefaultReplyPath(t *testing.T) {
	tg, _ := postJSON(t, `{"choices":[{"message":{"content":"hello there"}}]}`)
	r, err := tg.Send(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if r.Text != "hello there" {
		t.Errorf("reply = %q, want %q", r.Text, "hello there")
	}
}

// A path that does not exist in the payload is the most common misconfiguration, and the error
// has to say so rather than returning an empty reply that reads as "the agent said nothing".
func TestJSONReportsAMissingReplyPath(t *testing.T) {
	tg, _ := postJSON(t, `{"result":{"text":"hello"}}`)
	if _, err := tg.Send(context.Background(), "hi"); err == nil {
		t.Error("a reply path that is not in the payload returned no error")
	}
}

func TestJSONHonoursACustomReplyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"answer":"custom path"}}`))
	}))
	defer srv.Close()
	tg, err := NewJSON(Config{URL: srv.URL, Extra: map[string]string{"reply-path": "data.answer"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := tg.Send(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if r.Text != "custom path" {
		t.Errorf("reply = %q, want %q", r.Text, "custom path")
	}
}

// {{json}} exists so a prompt containing a quote cannot break the request body. That guarantee is
// the whole reason it is worth a test: the default envelope uses it, and the tool sends attacker-
// controlled text.
func TestJSONPlaceholderEscapesThePrompt(t *testing.T) {
	const tpl = `{"message":{{json}}}`
	body, err := renderTemplate(tpl, `he said "hello"`+"\n")
	if err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal(body, &probe); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v (%s)", err, body)
	}
	if probe["message"] != `he said "hello"`+"\n" {
		t.Errorf("message = %#v, want the prompt verbatim", probe["message"])
	}

	// {{prompt}} is raw text, so it is only usable where the template tolerates it.
	raw, err := renderTemplate(`{"text":{{prompt}}}`, "plain")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "plain") {
		t.Errorf("raw substitution lost the prompt: %s", raw)
	}

	// A template with neither placeholder falls back to a bare message envelope.
	fallback, err := renderTemplate(`{"unused":1}`, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fallback), "hello") {
		t.Errorf("the fallback envelope dropped the prompt: %s", fallback)
	}
}

// The default envelope is a guess, and a guess that produces invalid JSON would be reported as a
// transport failure rather than as the mistake it is.
func TestJSONRejectsABodyTemplateThatIsNotJSON(t *testing.T) {
	_, err := NewJSON(Config{URL: "http://x", Extra: map[string]string{"body": "{not json {{prompt}}"}})
	if err == nil {
		t.Error("a body template that is not JSON was accepted")
	}
}

func TestJSONNeedsAURL(t *testing.T) {
	if _, err := NewJSON(Config{}); err == nil {
		t.Error("NewJSON accepted an empty URL")
	}
}

func TestJSONDescribeRedactsCredentialsInTheURL(t *testing.T) {
	tg, err := NewJSON(Config{URL: "https://user:hunter2@example.test/v1/chat/completions"})
	if err != nil {
		t.Fatal(err)
	}
	d := tg.Describe()
	if strings.Contains(d, "hunter2") {
		t.Errorf("Describe leaked the password: %q", d)
	}
	if !strings.Contains(d, "example.test") {
		t.Errorf("Describe dropped the host entirely, which makes it useless: %q", d)
	}
}

func TestJSONRequestIsWellFormedJSON(t *testing.T) {
	tg, bodies := postJSON(t, `{"choices":[{"message":{"content":"ok"}}]}`)
	if _, err := tg.Send(context.Background(), `a "quoted" prompt`); err != nil {
		t.Fatal(err)
	}
	var probe map[string]any
	if err := json.Unmarshal([]byte((*bodies)[0]), &probe); err != nil {
		t.Fatalf("request body is not valid JSON: %v (%s)", err, (*bodies)[0])
	}
	if probe["message"] != `a "quoted" prompt` {
		t.Errorf("message = %#v, want the raw prompt", probe["message"])
	}
}

// The echo target is what the demo and the tests scan, so its reply must be the prompt it was
// given, or every end-to-end test is measuring the wrong thing.
func TestEchoRepliesWithThePrompt(t *testing.T) {
	e := NewEcho(nil)
	r, err := e.Send(context.Background(), "the exact prompt")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Text, "the exact prompt") {
		t.Errorf("echo reply = %q, want it to contain the prompt", r.Text)
	}
	if d := e.Describe(); !strings.Contains(d, "echo") {
		t.Errorf("Describe = %q, want it to name the target", d)
	}
}

func TestEchoFallsBackWhenTheScriptRunsOut(t *testing.T) {
	e := NewEcho([]string{"only one"})
	if _, err := e.Send(context.Background(), "first"); err != nil {
		t.Fatal(err)
	}
	// Asking again must still answer: a target that goes silent mid-scan looks like a break.
	if _, err := e.Send(context.Background(), "second"); err != nil {
		t.Errorf("the echo target stopped answering: %v", err)
	}
}

// The built-in transports must be discoverable by name, and an unknown name has to say what is
// available rather than failing with a bare error the caller cannot act on.
func TestConnectorRegistry(t *testing.T) {
	names := Names()
	joined := strings.Join(names, " ")
	for _, want := range []string{"echo", "openai", "json", "chat", "webform"} {
		if !strings.Contains(joined, want) {
			t.Errorf("connector %q is not registered; names = %v", want, names)
		}
	}
	if _, err := New("echo", Config{}); err != nil {
		t.Errorf("the echo connector failed to build: %v", err)
	}
	_, err := New("nope", Config{})
	if err == nil {
		t.Fatal("an unknown connector name was accepted")
	}
	var ue *UnknownConnectorError
	if !errors.As(err, &ue) {
		t.Fatalf("error is %T, want *UnknownConnectorError", err)
	}
	if ue.Name != "nope" || len(ue.Known) == 0 {
		t.Errorf("the error does not help the caller fix it: %+v", ue)
	}
}

func TestRegisterPanicsOnADuplicateName(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("registering a duplicate connector name did not panic; it would silently shadow one")
		}
	}()
	Register("echo", func(Config) (Target, error) { return NewEcho(nil), nil })
}

func TestStripHTMLRemovesTagsAndEntities(t *testing.T) {
	// Script bodies are dropped rather than kept: their content is code, not prose, and handing
	// it to the judge would hand a false positive to the markers.
	for in, want := range map[string]string{
		"<p>hello</p>":      "hello",
		"a &amp; b":         "a & b",
		"<b>bold</b> text":  "bold  text",
		"line<br/>break":    "line\nbreak",
		"no markup at all":  "no markup at all",
		"<script>bad()</s>": "",
	} {
		if got := strings.TrimSpace(stripHTML(in)); got != want {
			t.Errorf("stripHTML(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCollapseAndClipBoundTheOutput(t *testing.T) {
	// collapse trims each line and drops the blank ones, so a ragged reply reaches the judge with
	// no leading indentation and no runs of empty lines.
	if got := collapse("a   b\n\n\tc"); got != "a   b\nc" {
		t.Errorf("collapse = %q, want %q", got, "a   b\nc")
	}
	long := strings.Repeat("x", 5000)
	if got := clip(long); len([]rune(got)) > 5000 {
		t.Errorf("clip returned %d runes, want it bounded", len([]rune(got)))
	}
	if got := clip("short"); got != "short" {
		t.Errorf("clip altered a short string: %q", got)
	}
}
