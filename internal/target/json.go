package target

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// jsonTarget reaches an agent that does not speak the OpenAI shape, by letting
// the user describe both the request and where the answer lives in the reply.
//
// It is the connector that makes the scanner usable against a bespoke internal
// agent without writing Go: point --body at a template and --reply-path at a
// dotted path, and it works.
type jsonTarget struct {
	cfg      Config
	bodyTpl  string
	replySep string
}

// NewJSON builds a target from a request template and a dotted reply path.
func NewJSON(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("json connector needs --url")
	}
	tpl := cfg.Extra["body"]
	if tpl == "" {
		tpl = `{"message":{{json}}}`
	}
	path := cfg.Extra["reply-path"]
	if path == "" {
		path = "choices.0.message.content"
	}
	if _, ok := parseTemplate(tpl); !ok {
		return nil, fmt.Errorf("body template is not valid JSON once the prompt is substituted")
	}
	return &jsonTarget{cfg: cfg, bodyTpl: tpl, replySep: path}, nil
}

func (j *jsonTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	body, err := renderTemplate(j.bodyTpl, prompt)
	if err != nil {
		return Reply{}, fmt.Errorf("render body: %w", err)
	}

	status, raw, elapsed, err := post(ctx, j.cfg, body, "application/json")
	if err != nil {
		return Reply{Latency: elapsed}, err
	}

	reply := Reply{Status: status, Latency: elapsed, Raw: raw}

	decoded, derr := decodeJSON(raw)
	if derr != nil {
		if status >= 200 && status < 300 {
			reply.Text = clip(stripHTML(raw))
		}
		return reply, nil
	}

	text, ok := dig(decoded, j.replySep)
	if !ok {
		if e, found := dig(decoded, "error.message"); found {
			return reply, fmt.Errorf("target returned an error: %s", e)
		}
		return reply, fmt.Errorf("no value at reply path %q", j.replySep)
	}
	reply.Text = clip(text)
	return reply, nil
}

func (j *jsonTarget) Describe() string {
	return fmt.Sprintf("json %s (reply path %s)", redactURL(j.cfg.URL), j.replySep)
}

// renderTemplate substitutes {{prompt}} with the raw text and {{json}} with
// the prompt as a JSON string. A template containing neither gets a
// {"message": ...} envelope, which is the common enough case to be worth
// guessing.
func renderTemplate(tpl, prompt string) ([]byte, error) {
	// {{json}} substitutes the prompt as a JSON string, which is what keeps a
	// prompt containing a quote from breaking the body. It returns immediately
	// because the template has now been fully resolved.
	if strings.Contains(tpl, "{{json}}") {
		encoded, err := json.Marshal(prompt)
		if err != nil {
			return nil, err
		}
		return []byte(strings.ReplaceAll(tpl, "{{json}}", string(encoded))), nil
	}

	if strings.Contains(tpl, "{{prompt}}") {
		return []byte(strings.ReplaceAll(tpl, "{{prompt}}", prompt)), nil
	}

	// No placeholder at all: assume a bare {"message": ...} shape is wanted.
	encoded, err := json.Marshal(prompt)
	if err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf(`{"message":%s}`, encoded)), nil
}

// parseTemplate checks a template is JSON once the prompt is substituted.
func parseTemplate(tpl string) ([]byte, bool) {
	out := tpl
	if !strings.Contains(out, "{{prompt}}") && !strings.Contains(out, "{{json}}") {
		return nil, false
	}
	out = strings.ReplaceAll(out, "{{json}}", `"x"`)
	out = strings.ReplaceAll(out, "{{prompt}}", "x")
	var v any
	return []byte(out), json.Unmarshal([]byte(out), &v) == nil
}

func init() { Register("json", NewJSON) }
