package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// openaiTarget speaks the OpenAI chat-completions shape, which is what most
// self-hosted and proxied agents expose. Most such servers ignore the model
// field when they have exactly one model behind the endpoint, so it defaults
// to a placeholder rather than failing.
type openaiTarget struct {
	cfg   Config
	model string
}

// NewOpenAI builds a target for an OpenAI-compatible chat-completions endpoint.
func NewOpenAI(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("openai connector needs --url")
	}
	model := cfg.Extra["model"]
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &openaiTarget{cfg: cfg, model: model}, nil
}

func (o *openaiTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	body, err := json.Marshal(map[string]any{
		"model":    o.model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
		// A scan wants a short, repeatable answer, not a long varied one.
		"max_tokens":  512,
		"temperature": 0,
		"stream":      false,
	})
	if err != nil {
		return Reply{}, fmt.Errorf("encode request: %w", err)
	}

	status, raw, elapsed, err := post(ctx, o.cfg, body, "application/json")
	if err != nil {
		return Reply{Latency: elapsed}, err
	}

	reply := Reply{Status: status, Latency: elapsed, Raw: raw}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		// Not JSON: fall back to the body so a proxied error page still
		// reaches the judge rather than being silently dropped.
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}

	msg := digAny(decoded, "choices.0.message")
	if msg != nil {
		if calls, known := ExtractToolCalls(msg); known {
			reply.ToolCalls = calls
		}
	}

	text, ok := dig(decoded, "choices.0.message.content")
	if !ok {
		if e, found := dig(decoded, "error.message"); found {
			return reply, fmt.Errorf("target returned an error: %s", e)
		}
		// The message is there and its content is not a plain string. That is an answer, and
		// what it says is whatever text it holds — often none: a turn that only calls a tool
		// has a null content. Falling back to the raw body here handed the judge the whole
		// JSON envelope, tool arguments included, so a payload the agent passed to a tool was
		// matched as if the agent had said it.
		if m, isMessage := msg.(map[string]any); isMessage {
			reply.Text = clip(messageText(m))
			return reply, nil
		}
		// No message at all: this is not the OpenAI shape, and the body is the only evidence.
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}
	reply.Text = clip(text)
	return reply, nil
}

// messageText returns what an assistant message says when its content is not a plain string:
// the text parts of a content array joined in order, or the refusal a structured-output model
// writes beside a null content, or nothing.
func messageText(m map[string]any) string {
	var parts []string
	if list, ok := m["content"].([]any); ok {
		for _, item := range list {
			switch part := item.(type) {
			case string:
				parts = append(parts, part)
			case map[string]any:
				if t, ok := part["text"].(string); ok {
					parts = append(parts, t)
				}
			}
		}
	}
	if len(parts) == 0 {
		if refusal, ok := m["refusal"].(string); ok {
			return refusal
		}
	}
	return strings.Join(parts, "\n")
}

func (o *openaiTarget) Describe() string {
	return fmt.Sprintf("openai-compatible %s", redactURL(o.cfg.URL))
}

// redactURL strips credentials, query and fragment so a secret in a URL never
// reaches a report header or a log line.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "invalid-url"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func init() { Register("openai", NewOpenAI) }
