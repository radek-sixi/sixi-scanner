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
	"sync"
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

	start := time.Now()
	resp, err := clientFor(cfg).Do(req)
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

// clientKey is everything about a Config that changes how a connection is made.
type clientKey struct {
	timeout  time.Duration
	insecure bool
}

var (
	clientsMu sync.Mutex
	clients   = map[clientKey]*http.Client{}
)

// clientFor returns the client for a configuration, building it the first time it is asked for.
//
// A client is kept because a transport is: it owns the connection pool. Building one per request
// gave every request of an --insecure scan a pool of its own, so no connection was ever reused —
// each prompt paid for a new TLS handshake — and each abandoned pool kept its idle connection and
// the two goroutines that serve it until the idle timeout, ninety seconds later. A scan of a few
// hundred attempts held a few hundred sockets open against the target it was measuring.
func clientFor(cfg Config) *http.Client {
	key := clientKey{timeout: cfg.Timeout, insecure: cfg.Insecure}

	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[key]; ok {
		return c
	}

	c := &http.Client{Timeout: cfg.Timeout, CheckRedirect: sameHostOnly}
	if cfg.Insecure {
		// A copy of the default transport, so that skipping verification changes that and
		// nothing else: the proxy settings, the dial and idle timeouts and HTTP/2 stay as they
		// are for a verified scan.
		var tr *http.Transport
		if def, ok := http.DefaultTransport.(*http.Transport); ok {
			tr = def.Clone()
		} else {
			tr = &http.Transport{Proxy: http.ProxyFromEnvironment}
		}
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // opt-in, for self-signed staging endpoints
		c.Transport = tr
	}
	clients[key] = c
	return c
}

// maxRedirects is the standard library's own limit, restated because setting CheckRedirect
// replaces it.
const maxRedirects = 10

// sameHostOnly follows a redirect only while it stays on the host the request was addressed to.
//
// A 307 or 308 is re-sent as it was: the method, the body and every header the caller set. The
// standard client drops Authorization and Cookie when the host changes and nothing else, so an
// endpoint that answered with a redirect elsewhere was handed the prompt and the X-Api-Key that
// came with it. The operator named one address; what is sent goes to that host or not at all.
func sameHostOnly(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	// Measured from the first request, so a chain cannot walk away one hop at a time.
	from := via[0].URL
	if !strings.EqualFold(req.URL.Hostname(), from.Hostname()) {
		return fmt.Errorf("the endpoint redirected to another host (%s) and was not followed: the "+
			"prompt and the request headers are only sent to the host the scan was pointed at", req.URL.Host)
	}
	if from.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("the endpoint redirected from https to %s and was not followed: the "+
			"request is not re-sent unencrypted", req.URL.Scheme)
	}
	return nil
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
