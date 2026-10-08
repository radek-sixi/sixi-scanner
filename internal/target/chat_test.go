package target

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The chat connector is the only one that can hold a conversation, so what matters is not that it
// sends a prompt but that it keeps turns together, reports which conversation it is in, and does
// not confuse "no trace" with "nothing called".

// chatServer records every request body and replies with a canned body.
type chatServer struct {
	t     *testing.T
	reply func(n int) (int, string)

	// mu guards bodies: a scan sends from several techniques at once, and the concurrency test
	// below deliberately does the same, so the recorder has to be as safe as the connector.
	mu     sync.Mutex
	bodies []map[string]any
}

func (c *chatServer) sent() []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]map[string]any(nil), c.bodies...)
}

func (c *chatServer) start() *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			c.t.Errorf("the connector sent a body that is not JSON: %v", err)
		}
		c.mu.Lock()
		c.bodies = append(c.bodies, body)
		n := len(c.bodies) - 1
		c.mu.Unlock()
		status, out := c.reply(n)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(out))
	}))
	c.t.Cleanup(srv.Close)
	return srv
}

func newChat(t *testing.T, srv *httptest.Server) Target {
	t.Helper()
	tg, err := NewChat(Config{URL: srv.URL + "/chat"})
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestChatReadsTheReplyField(t *testing.T) {
	c := &chatServer{t: t, reply: func(int) (int, string) { return 200, `{"reply":"your refund is on the way"}` }}
	tg := newChat(t, c.start())

	r, err := tg.Send(context.Background(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if r.Text != "your refund is on the way" {
		t.Errorf("reply text is %q", r.Text)
	}
	if r.Status != 200 || r.Latency <= 0 {
		t.Errorf("status %d latency %v; both are reported for every connector", r.Status, r.Latency)
	}
}

// Without a conversation in the context the connector is a plain single-turn request, so pointing it
// at an endpoint that has no notion of one still works.
func TestChatCarriesTheConversationFromTheContext(t *testing.T) {
	c := &chatServer{t: t, reply: func(int) (int, string) { return 200, `{"reply":"ok"}` }}
	tg := newChat(t, c.start())

	if _, err := tg.Send(context.Background(), "hi"); err != nil {
		t.Fatal(err)
	}
	if _, has := c.sent()[0]["session_id"]; has {
		t.Error("a conversation id was sent although none was set")
	}
	if c.sent()[0]["message"] != "hi" {
		t.Errorf("the prompt was not carried as `message`: %v", c.sent()[0])
	}

	ctx := WithSession(context.Background(), "probe-x-r1-a0")
	if _, err := tg.Send(ctx, "again"); err != nil {
		t.Fatal(err)
	}
	if c.sent()[1]["session_id"] != "probe-x-r1-a0" {
		t.Errorf("the conversation id was not carried: %v", c.sent()[1])
	}
}

// The id travels per request, so two sends made with different contexts reach the endpoint as two
// conversations even though they came from one connector. Holding it on the connector instead was
// measured to let concurrently-running techniques overwrite each other's conversation.
func TestChatKeepsConcurrentConversationsApart(t *testing.T) {
	c := &chatServer{t: t, reply: func(int) (int, string) { return 200, `{"reply":"ok"}` }}
	tg := newChat(t, c.start())

	var wg sync.WaitGroup
	for _, id := range []string{"probe-a-r1-a0", "probe-b-r1-a0", "probe-c-r1-a0"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			for range 3 {
				if _, err := tg.Send(WithSession(context.Background(), id), "x"); err != nil {
					t.Error(err)
					return
				}
			}
		}(id)
	}
	wg.Wait()

	sent := c.sent()
	if len(sent) != 9 {
		t.Fatalf("got %d requests, want 9", len(sent))
	}
	counts := map[string]int{}
	for i, b := range sent {
		id, ok := b["session_id"].(string)
		if !ok || id == "" {
			t.Fatalf("request %d carried no conversation: %v", i, b)
		}
		counts[id]++
	}
	if len(counts) != 3 {
		t.Errorf("got %d conversations, want 3: %v", len(counts), counts)
	}
	for id, n := range counts {
		if n != 3 {
			t.Errorf("conversation %q carried %d requests, want 3", id, n)
		}
	}
}

// The session id is what keeps one attempt's cumulative state out of the next, so reusing one
// across attempts would let a cap-split probe report a split the agent never performed.
func TestSessionKeyIsUniquePerAttempt(t *testing.T) {
	seen := map[string]bool{}
	for _, round := range []int{1, 2} {
		for attempt := range 4 {
			k := SessionKey("probe.llm06.refund-cap-split", round, attempt)
			if seen[k] {
				t.Errorf("session id %q was reused", k)
			}
			seen[k] = true
			if strings.ContainsAny(k, "./") {
				t.Errorf("session id %q carries a path character and could be mistaken for a path", k)
			}
		}
	}
	if SessionKey("a", 1, 0) == SessionKey("b", 1, 0) {
		t.Error("two techniques shared a session id")
	}
}

// "No trace reported" and "nothing was called" are different facts, and conflating them is what
// makes a false action claim unadjudicable. The three-state distinction has to survive this path.
func TestChatDistinguishesNoTraceFromNothingCalled(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantLen  int
		wantSeen bool
	}{
		{"no trace key at all", `{"reply":"done"}`, 0, false},
		{"null trace", `{"reply":"done","tool_calls":null}`, 0, true},
		{"trace present and empty", `{"reply":"done","tool_calls":[]}`, 0, true},
		{"one call, flat", `{"reply":"done","tool_calls":[{"name":"issue_refund","arguments":{"amount":30}}]}`, 1, true},
		{"one call, openai shape", `{"reply":"done","message":{"role":"assistant","tool_calls":[{"function":{"name":"issue_refund","arguments":"{\"amount\":30}"}}]}}`, 1, true},
		{"nested message with no trace falls through to the root", `{"reply":"done","message":{"role":"assistant"},"tool_calls":[{"name":"issue_refund"}]}`, 1, true},
		{"nested message without a trace, root without either", `{"reply":"done","message":{"role":"assistant"}}`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &chatServer{t: t, reply: func(int) (int, string) { return 200, tc.body }}
			tg := newChat(t, c.start())
			r, err := tg.Send(context.Background(), "go")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.ToolCalls) != tc.wantLen {
				t.Errorf("got %d tool calls, want %d", len(r.ToolCalls), tc.wantLen)
			}
			// The distinction is nil versus empty, not the length: nil means the endpoint reported
			// no trace at all, and an empty non-nil slice means it reported a trace in which the
			// agent called nothing. Collapsing the two makes a false action claim unadjudicable in
			// both directions, so it is asserted rather than assumed.
			switch {
			case tc.wantSeen && r.ToolCalls == nil:
				t.Error("the endpoint reported a trace, so the slice must be non-nil even when empty")
			case !tc.wantSeen && r.ToolCalls != nil:
				t.Errorf("no trace was reported, so ToolCalls must stay nil rather than asserting a fact: %#v", r.ToolCalls)
			}
		})
	}
}

// An endpoint that answers with something other than the expected shape should still put something
// in front of the judge rather than failing the scan.
func TestChatSurvivesResponsesItDoesNotUnderstand(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   string
		errHas string
	}{
		{"plain text", 200, "just some words", "just some words", ""},
		{"html error page", 200, "<html><body><p>gateway down</p></body></html>", "gateway down", ""},
		{"structured error", 500, `{"error":{"message":"session expired"}}`, "", "session expired"},
		// A failure status with no error.message must not be dressed up as a reply, and must not fail
		// the send either: the body is kept so an operator can see what came back.
		{"failure with no error message", 503, `{"detail":"upstream unavailable"}`, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &chatServer{t: t, reply: func(int) (int, string) { return tc.status, tc.body }}
			tg := newChat(t, c.start())
			r, err := tg.Send(context.Background(), "go")
			if tc.errHas != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errHas) {
					t.Fatalf("err = %v, want it to mention %q", err, tc.errHas)
				}
				return
			}
			if err != nil {
				t.Fatalf("a response the connector did not expect failed the send: %v", err)
			}
			if !strings.Contains(r.Text, tc.want) {
				t.Errorf("text is %q, want it to contain %q", r.Text, tc.want)
			}
		})
	}
}

// A transport failure has to surface as an error rather than as an empty reply, or a scan would
// report an agent that was never actually asked anything.
func TestChatReportsATransportFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL + "/chat"
	srv.Close() // nothing is listening now

	tg, err := NewChat(Config{URL: url})
	if err != nil {
		t.Fatal(err)
	}
	r, err := tg.Send(context.Background(), "go")
	if err == nil {
		t.Fatal("an unreachable endpoint was reported as a reply")
	}
	if r.Text != "" {
		t.Errorf("a failed send produced text %q; there was no agent to answer", r.Text)
	}
}

func TestChatNeedsAURL(t *testing.T) {
	if _, err := NewChat(Config{}); err == nil {
		t.Fatal("a chat connector with no URL was accepted")
	}
}

// Describe is what a report shows, so it must name the host without the password. It deliberately
// does not name a conversation: a report describes the target, and a scan runs many conversations
// through one connector.
func TestChatDescribeRedactsCredentials(t *testing.T) {
	tg, err := NewChat(Config{URL: "http://u:secret@example.com/chat"})
	if err != nil {
		t.Fatal(err)
	}
	if d := tg.Describe(); !strings.Contains(d, "example.com") || strings.Contains(d, "secret") {
		t.Errorf("Describe is %q; it should name the host without the password", d)
	}
	if !tg.(Sessioner).SupportsSessions() {
		t.Error("the chat connector does not claim session support")
	}
}

// History is for reports and tests, so it must be a copy: a caller mutating it cannot reach into
// the connector's own record of the conversation.
func TestChatHistoryIsACopy(t *testing.T) {
	c := &chatServer{t: t, reply: func(int) (int, string) { return 200, `{"reply":"ack"}` }}
	tg := newChat(t, c.start())
	if _, err := tg.Send(context.Background(), "one"); err != nil {
		t.Fatal(err)
	}
	h, ok := tg.(interface{ History() []string })
	if !ok {
		t.Fatal("History is not reachable; a report could not show the conversation")
	}
	got := h.History()
	if len(got) != 2 || got[0] != "one" || got[1] != "ack" {
		t.Fatalf("history is %v, want the prompt and the reply", got)
	}
	got[0] = "tampered"
	if again := h.History(); again[0] != "one" {
		t.Error("History handed back its own storage; a caller can corrupt the transcript")
	}
}
