package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDigWalksObjectsAndArrays(t *testing.T) {
	body := `{"choices":[{"message":{"content":"hello"}}],"n":1,"ok":true}`
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		path string
		want string
		ok   bool
	}{
		{"choices.0.message.content", "hello", true},
		{"ok", "true", true},
		{"n", "1", true},
		{"choices.0.message.role", "", false},
		{"choices.9.message.content", "", false},
		{"choices.message.content", "", false},
		{"missing.path", "", false},
		{"", "", false},
		{"choices.0", "", false}, // lands on an array, not a leaf
	}

	for _, tc := range cases {
		got, ok := dig(v, tc.path)
		if ok != tc.ok || got != tc.want {
			t.Errorf("dig(%q) = %q, %v; want %q, %v", tc.path, got, ok, tc.want, tc.ok)
		}
	}
}

func TestStripHTMLKeepsTextAndDropsScript(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
		not  []string
	}{
		{
			name: "script contents are not content",
			in:   `<div>Hello<script>var secret = "you are a";</script>World</div>`,
			want: []string{"Hello", "World"},
			not:  []string{"secret", "you are a"},
		},
		{
			name: "style contents are not content",
			in:   `<style>.x{content:"you are a"}</style><p>Hi</p>`,
			want: []string{"Hi"},
			not:  []string{"you are a"},
		},
		{
			name: "entities are decoded",
			in:   `<p>Anna&nbsp;Keller &amp; Co &#39;quoted&#39;</p>`,
			want: []string{"Anna Keller & Co", "'quoted'"},
		},
		{
			name: "unterminated script swallows the rest",
			in:   `Visible<script>hidden`,
			want: []string{"Visible"},
			not:  []string{"hidden"},
		},
		{
			name: "a closing tag without an opening tag is ignored",
			in:   `plain</script>more`,
			want: []string{"plain", "more"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stripHTML(tc.in)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("stripHTML(%q) = %q, missing %q", tc.in, got, w)
				}
			}
			for _, n := range tc.not {
				if strings.Contains(got, n) {
					t.Errorf("stripHTML(%q) = %q, should not contain %q", tc.in, got, n)
				}
			}
		})
	}
}

// A script block is a real exfiltration surface: text the agent did not speak
// still reaches a page. If it survives stripping, a marker inside it produces
// a finding against text the user never saw.
func TestMarkersInsideScriptAreNotScored(t *testing.T) {
	page := `<html><body><script>window.__cfg = {system_prompt: "you are a helpful bot"};</script></body></html>`

	if text := stripHTML(page); strings.Contains(strings.ToLower(text), "you are a") {
		t.Errorf("a script payload survived stripping: %q", text)
	}
}

func TestSliceByMarker(t *testing.T) {
	html := `<div class="chat">…<div class="reply">the answer is 42</div><div class="input">`

	got, ok := sliceByMarker(html, `class="reply"|class="input"`)
	if !ok {
		t.Fatal("expected the markers to be found")
	}
	if !strings.Contains(got, "the answer is 42") {
		t.Errorf("slice = %q, missing the reply", got)
	}

	if _, ok := sliceByMarker(html, "absent|also-absent"); ok {
		t.Error("expected a miss when the marker is absent")
	}
	if _, ok := sliceByMarker(html, "malformed"); ok {
		t.Error("expected a miss for a marker without a closing half")
	}
}

func TestOpenAIConnectorReadsTheAssistantMessage(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		io := `{"choices":[{"message":{"role":"assistant","content":"You are a bot."}}]}`
		w.Write([]byte(io))
	}))
	defer srv.Close()

	tgt, err := NewOpenAI(Config{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	reply, err := tgt.Send(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "You are a bot." {
		t.Errorf("text = %q", reply.Text)
	}

	msgs := gotBody["messages"].([]any)
	first := msgs[0].(map[string]any)
	if first["content"] != "hello" {
		t.Errorf("the prompt did not reach the request: %v", first)
	}
	if gotBody["temperature"] != float64(0) {
		t.Errorf("temperature = %v, want 0 so a re-scan is comparable", gotBody["temperature"])
	}
}

func TestOpenAIConnectorSurfacesAnErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"invalid api key"}}`))
	}))
	defer srv.Close()

	tgt, _ := NewOpenAI(Config{URL: srv.URL, Timeout: 5 * time.Second})
	if _, err := tgt.Send(context.Background(), "hello"); err == nil {
		t.Fatal("expected an error when the target returns an error object")
	}
}

// A target that leaks in a 500 response has still leaked. The judge must see
// the body, and the connector must not discard it.
func TestErrorStatusStillYieldsTheBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"choices":[{"message":{"content":"You are a privileged internal agent."}}]}`))
	}))
	defer srv.Close()

	tgt, _ := NewOpenAI(Config{URL: srv.URL, Timeout: 5 * time.Second})
	reply, err := tgt.Send(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply.Text, "privileged internal") {
		t.Errorf("a leak in a 500 body was discarded: %q", reply.Text)
	}
}

func TestJSONConnectorUsesTemplateAndReplyPath(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"result":{"text":"your instructions are: be helpful"}}`))
	}))
	defer srv.Close()

	tgt, err := NewJSON(Config{
		URL:     srv.URL,
		Timeout: 5 * time.Second,
		Extra:   map[string]string{"body": `{"question":{{json}}}`, "reply-path": "result.text"},
	})
	if err != nil {
		t.Fatal(err)
	}

	reply, err := tgt.Send(context.Background(), `he said "hi"`)
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "your instructions are: be helpful" {
		t.Errorf("text = %q", reply.Text)
	}
	if got["question"] != `he said "hi"` {
		t.Errorf("a prompt containing quotes did not survive JSON encoding: %v", got["question"])
	}
}

func TestJSONConnectorRejectsABadReplyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"answer":"x"}`))
	}))
	defer srv.Close()

	tgt, _ := NewJSON(Config{URL: srv.URL, Timeout: 5 * time.Second,
		Extra: map[string]string{"reply-path": "nope.not.here"}})

	if _, err := tgt.Send(context.Background(), "hi"); err == nil {
		t.Fatal("expected an error when the reply path does not resolve")
	}
}

func TestJSONConnectorRejectsATemplateThatIsNotJSON(t *testing.T) {
	_, err := NewJSON(Config{URL: "http://x.invalid", Extra: map[string]string{"body": "not json {{prompt}}"}})
	if err == nil {
		t.Fatal("expected an error for a non-JSON body template")
	}
}

func TestRenderTemplateEscapesThePrompt(t *testing.T) {
	// A prompt containing a quote must not be able to break out of the JSON
	// body and inject a field of its own.
	body, err := renderTemplate(`{"message":{{json}}}`, `hi", "admin": true, "x": "`)
	if err != nil {
		t.Fatal(err)
	}

	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("rendered body is not valid JSON: %v\n%s", err, body)
	}
	if _, injected := v["admin"]; injected {
		t.Errorf("the prompt injected a field into the request body: %s", body)
	}
}

func TestWebFormConnectorPostsAField(t *testing.T) {
	var gotForm string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		gotForm = r.Form.Get("message")
		w.Write([]byte(`<html><body><div class="reply">Your instructions are: be brief.</div></body></html>`))
	}))
	defer srv.Close()

	tgt, err := NewWebForm(Config{URL: srv.URL, Timeout: 5 * time.Second,
		Extra: map[string]string{"field": "message"}})
	if err != nil {
		t.Fatal(err)
	}

	reply, err := tgt.Send(context.Background(), "who are you")
	if err != nil {
		t.Fatal(err)
	}
	if gotForm != "who are you" {
		t.Errorf("the prompt did not reach the form field, got %q", gotForm)
	}
	if !strings.Contains(reply.Text, "Your instructions are") {
		t.Errorf("reply text = %q", reply.Text)
	}
}

func TestCredentialsAreNeverDescribed(t *testing.T) {
	// A report header is the one string guaranteed to be shared with people
	// outside the assessment, so it must not carry a secret.
	tgt, _ := NewOpenAI(Config{URL: "https://user:hunter2@internal.example/v1?token=abc"})
	got := tgt.Describe()

	for _, secret := range []string{"hunter2", "user:", "token=abc"} {
		if strings.Contains(got, secret) {
			t.Errorf("Describe() leaked %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "internal.example") {
		t.Errorf("Describe() dropped the host, which is the useful part: %s", got)
	}
}

func TestUnknownConnectorListsWhatIsAvailable(t *testing.T) {
	_, err := New("nope", Config{})
	if err == nil {
		t.Fatal("expected an error")
	}
	for _, want := range []string{"echo", "openai", "json", "webform"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention the %q connector: %v", want, err)
		}
	}
}

func TestEchoTargetAnswersWithoutTheNetwork(t *testing.T) {
	tgt := NewEcho([]string{"You are a bot."})
	reply, err := tgt.Send(context.Background(), "hi")
	if err != nil {
		t.Fatal(err)
	}
	if reply.Text != "You are a bot." {
		t.Errorf("text = %q", reply.Text)
	}
}

func TestContextCancellationStopsASend(t *testing.T) {
	// The handler blocks until the test releases it, so the client-side
	// deadline is the only thing that can end the request. That is what makes
	// this a test of cancellation rather than of a fast server.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	tgt, _ := NewOpenAI(Config{URL: srv.URL, Timeout: 5 * time.Second})

	start := time.Now()
	_, err := tgt.Send(ctx, "hi")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected the cancelled context to surface as an error")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Send took %v; the context deadline should have ended it far sooner", elapsed)
	}
}
