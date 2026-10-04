package target

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// webformTarget posts to an HTML form, for the website-chatbot case where there
// is no API to speak to.
//
// It sends one form-encoded field and reads the reply as text out of the
// returned page. It does not run JavaScript, so a chatbot that renders its
// answers client-side will come back empty — the connector says so rather than
// reporting a false clean.
type webformTarget struct {
	cfg      Config
	field    string
	selector string
}

// NewWebForm builds a target for an HTML form.
func NewWebForm(cfg Config) (Target, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webform connector needs --url")
	}
	field := cfg.Extra["field"]
	if field == "" {
		field = "message"
	}
	return &webformTarget{
		cfg:      cfg,
		field:    field,
		selector: cfg.Extra["reply-selector"],
	}, nil
}

func (w *webformTarget) Send(ctx context.Context, prompt string) (Reply, error) {
	form := url.Values{w.field: []string{prompt}}
	for k, v := range w.cfg.Extra {
		if strings.HasPrefix(k, "field:") {
			form.Set(strings.TrimPrefix(k, "field:"), v)
		}
	}

	status, raw, elapsed, err := post(ctx, w.cfg, []byte(form.Encode()),
		"application/x-www-form-urlencoded")
	if err != nil {
		return Reply{Latency: elapsed}, err
	}

	reply := Reply{Status: status, Latency: elapsed, Raw: raw}
	if status < 200 || status >= 300 {
		return reply, nil
	}

	text := stripHTML(raw)
	if w.selector != "" {
		if section, ok := sliceByMarker(raw, w.selector); ok {
			text = stripHTML(section)
		}
	}
	reply.Text = clip(text)

	if strings.TrimSpace(reply.Text) == "" {
		return reply, fmt.Errorf(
			"page returned no readable text; if the chatbot renders client-side, use the json or openai connector instead")
	}
	return reply, nil
}

func (w *webformTarget) Describe() string {
	return fmt.Sprintf("webform %s (field %q)", redactURL(w.cfg.URL), w.field)
}

// sliceByMarker returns the HTML between the last occurrence of open and the
// first following occurrence of close. It is a stand-in for a CSS selector and
// is documented as such; for a page whose answers are already the only text
// there, leave the selector unset.
func sliceByMarker(html, open string) (string, bool) {
	parts := strings.Split(open, "|")
	if len(parts) != 2 {
		return "", false
	}
	i := strings.LastIndex(html, parts[0])
	if i < 0 {
		return "", false
	}
	j := strings.Index(html[i+len(parts[0]):], parts[1])
	if j < 0 {
		return "", false
	}
	return html[i+len(parts[0]) : i+len(parts[0])+j], true
}

func init() { Register("webform", NewWebForm) }
