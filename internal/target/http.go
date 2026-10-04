package target

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// post sends one request and returns the status, body and elapsed time. Every
// HTTP transport funnels through here so timeout, header and body-capture
// behaviour is identical across them.
func post(ctx context.Context, cfg Config, body []byte, contentType string) (int, string, time.Duration, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return 0, "", 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "sixi-scanner")
	// A scan must not be served a cached answer.
	req.Header.Set("Cache-Control", "no-store")
	for k, v := range cfg.Headers {
		if k == "" {
			continue
		}
		req.Header.Set(k, v)
	}

	client := &http.Client{Timeout: cfg.Timeout}
	if cfg.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // opt-in, for self-signed staging endpoints
		}
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return 0, "", elapsed, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	// Cap the read so a hostile or broken endpoint cannot exhaust memory. The
	// judge only ever looks at the first part of a reply.
	const maxBody = 2 << 20 // 2 MiB
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, "", elapsed, fmt.Errorf("read response: %w", err)
	}
	return resp.StatusCode, string(raw), elapsed, nil
}

// dig walks a dotted path with numeric segments through decoded JSON and
// returns the string at the end of it.
//
//	"choices.0.message.content" -> the assistant message content
//	"reply.text"                 -> a field named text under a field named reply
//
// It is the mechanism the json transport uses so a non-OpenAI agent can be
// pointed at without writing Go.
func dig(v any, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return "", false
			}
			cur = next
		case []any:
			i, err := atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return "", false
			}
			cur = node[i]
		default:
			return "", false
		}
	}

	switch leaf := cur.(type) {
	case string:
		return leaf, true
	case float64, bool, int64:
		return fmt.Sprint(leaf), true
	case nil:
		return "", false
	default:
		// A path that lands on an object or array is usually a mistake in the
		// path, so say so rather than dumping JSON into the transcript.
		return "", false
	}
}

func atoi(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty index")
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a number: %q", s)
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

// decodeJSON parses a body, tolerating the JSONP wrapper some web endpoints add.
func decodeJSON(body string) (any, error) {
	trimmed := strings.TrimSpace(body)
	if trimmed == "" {
		return nil, fmt.Errorf("empty response body")
	}
	var v any
	if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
		return v, nil
	}
	if open, close := strings.Index(trimmed, "("), strings.LastIndex(trimmed, ")"); open > 0 && close > open {
		var v any
		if err := json.Unmarshal([]byte(trimmed[open+1:close]), &v); err == nil {
			return v, nil
		}
	}
	return nil, fmt.Errorf("response is not JSON")
}
