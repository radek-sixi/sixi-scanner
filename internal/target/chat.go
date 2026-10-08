package target

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Sessioner is implemented by connectors that can hold a conversation across Send calls.
//
// It is optional on purpose. Most endpoints are stateless and a scanner pointed at one should work
// unchanged, so this is a second interface rather than a method on Target — and a technique that
// needs a session can say so, because a sequence scored against a target that quietly dropped the
// session would be measuring nothing.
//
// It deliberately has no method for opening a session. The conversation id travels in the context,
// per request, because a scan runs several techniques at once and a single id held on the connector
// would be overwritten by whichever technique started next: two multi-turn probes would then share
// one conversation, each attack's opening turn would be answered inside the other's, and the
// evidence in the report would describe a conversation that never happened. Holding the id as
// connector state was measured to do exactly that.
type Sessioner interface {
	// SupportsSessions reports that this connector can join a conversation named in the context.
	// See WithSession and SessionFrom.
	SupportsSessions() bool
}

type sessionCtxKey struct{}

// WithSession returns a context that identifies the conversation subsequent Sends belong to.
//
// It is set once per attempt rather than once per technique, so an endpoint that keys cumulative
// state on the session id cannot carry one attempt's running total into the next — which would let a
// cap-split probe report a split the agent never performed.
func WithSession(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, sessionCtxKey{}, id)
}

// SessionFrom reads the conversation id a Send should join, if one was set.
func SessionFrom(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionCtxKey{}).(string)
	return id, ok && id != ""
}

// chatTarget speaks the simple request/response endpoint that keeps a conversation server-side.
//
// It exists because the OpenAI-compatible path cannot express some of the things worth testing. A
// stateless connector has to resend the whole history to make the agent aware of it, and a server
// that tracks state per caller can also be asked about things that only exist across turns -- a
// cumulative refund total, a poisoned instruction stored on turn one and acted on in turn two. Those
// are not reachable by resending text, because the state being tested is the server's, not the
// transcript's.
type chatTarget struct {
	cfg     Config
	url     string
	timeout time.Duration

	// history keeps what the agent said, so a caller can see the conversation in a report without
	// the target having to expose it. Guarded because a scan sends from several techniques at once.
	mu      sync.Mutex
	history []string
}

func NewChat(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("chat connector needs --url")
	}
	return &chatTarget{cfg: cfg, url: cfg.URL, timeout: 30 * time.Second}, nil
}

// SupportsSessions implements Sessioner.
func (c *chatTarget) SupportsSessions() bool { return true }

// Send implements Target. It joins the conversation named in the context, if any; with none set it
// is a plain single-turn request, so the connector is usable either way.
func (c *chatTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	body := map[string]any{"message": prompt}
	if id, ok := SessionFrom(ctx); ok {
		body["session_id"] = id
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return Reply{}, fmt.Errorf("encode request: %w", err)
	}

	status, raw, elapsed, err := post(ctx, c.cfg, encoded, "application/json")
	reply := Reply{Status: status, Latency: elapsed, Raw: raw}
	if err != nil {
		return reply, err
	}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		// Not JSON: hand back the body so a proxied error page still reaches the judge.
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}
	text, ok := dig(decoded, "reply")
	if !ok {
		if e, found := dig(decoded, "error.message"); found {
			return reply, fmt.Errorf("target returned an error: %s", e)
		}
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}
	reply.Text = clip(text)
	c.mu.Lock()
	c.history = append(c.history, prompt, reply.Text)
	c.mu.Unlock()

	// A chat endpoint that reports the tools it saw is the only way a false action claim can be
	// adjudicated, so it is read when present and its absence is not treated as evidence either way.
	//
	// Both places are tried because the two common shapes disagree about where a trace lives: an
	// OpenAI-compatible reply nests it under `message`, while a simple chat endpoint that returns
	// `{reply, tool_calls}` puts it beside the reply. Trying the first and stopping there would
	// silently report "no trace" for an endpoint that was reporting one all along -- which, per
	// ExtractToolCalls, is exactly the condition that makes every trace-based check inert.
	if calls, known := chatTrace(digAny(decoded, "message")); known {
		reply.ToolCalls = calls
	} else if calls, known := ExtractToolCalls(decoded); known {
		reply.ToolCalls = calls
	}
	return reply, nil
}

// chatTrace reads a trace from a nested message object. A message that exists but carries no
// tool_calls key reports unknown rather than an empty list, so that the caller falls through to the
// other shape instead of mistaking "this object said nothing about tools" for "it called nothing".
func chatTrace(msg any) ([]ToolCall, bool) {
	obj, isObject := msg.(map[string]any)
	if !isObject {
		return nil, false
	}
	if _, present := obj["tool_calls"]; !present {
		return nil, false
	}
	return ExtractToolCalls(obj)
}

func (c *chatTarget) Describe() string { return "chat " + redactURL(c.url) }

// History returns the conversation so far, for a report or a test. It is not part of Target because
// a transcript the agent already returns is not something every endpoint provides.
func (c *chatTarget) History() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.history...)
}

func init() { Register("chat", NewChat) }

// SessionKey builds a conversation id that is unique per attempt.
//
// It has to be unique, not merely stable: an endpoint that keys its state on the session id would
// otherwise carry one attempt's cumulative state into the next, and a technique that measures a
// cap would report a split the agent never performed. The dots in a technique id are fine in a
// header value, but they are replaced anyway so the id cannot be mistaken for a path.
func SessionKey(techniqueID string, round, attempt int) string {
	return strings.NewReplacer(".", "-", "/", "-").Replace(techniqueID) +
		fmt.Sprintf("-r%d-a%d", round, attempt)
}
