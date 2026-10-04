package target

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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

	text, ok := dig(decoded, "choices.0.message.content")
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
	return reply, nil
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
