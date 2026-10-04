// Package target is where a scan sends its prompts.
//
// A target is the smallest useful thing: something that takes a prompt and
// returns text. Every transport in this package implements it, and the engine
// never learns which one it has.
//
// Adding a transport means implementing Send and Describe. Nothing else in the
// scanner changes.
package target

import (
	"context"
	"time"
)

// Reply is one response from a target.
type Reply struct {
	// Text is the agent's answer, extracted from whatever transport was used.
	// It is what the judge reads.
	Text string

	// Status is the HTTP status, or 0 for a transport with no HTTP semantics.
	Status int

	// Latency is the round trip.
	Latency time.Duration

	// Raw is the undecoded body, kept for the transcript and for debugging a
	// connector. It may contain data the target chose to disclose, so reports
	// treat it as evidence rather than as safe to publish.
	Raw string
}

// Target is a conversation partner under test.
type Target interface {
	// Send delivers prompt and returns the agent's reply.
	//
	// Implementations must respect ctx: a scan that is cancelled mid-run
	// should stop promptly rather than finish every remaining technique.
	Send(ctx context.Context, prompt string) (Reply, error)

	// Describe returns a one-line, credential-free identification of the
	// target for the report header, e.g. "openai-compatible https://host/v1".
	Describe() string
}

// Factory builds a target from parsed flags. Registering one makes it
// available to --target by name.
type Factory func(Config) (Target, error)

// Config carries the connection settings shared by the HTTP transports.
type Config struct {
	// URL is the endpoint to POST to.
	URL string

	// Headers are added to every request. Values may hold $PROMPT and
	// $BODY if the transport substitutes them.
	Headers map[string]string

	// Timeout bounds a single request.
	Timeout time.Duration

	// Insecure skips TLS verification. It exists for scanning a staging
	// endpoint with a self-signed certificate and is reported in the scan
	// header when set.
	Insecure bool

	// Extra is transport-specific settings, e.g. the model name for
	// openai or the reply path for json.
	Extra map[string]string
}

// registry holds the known transports by name.
var registry = map[string]Factory{}

// Register adds a transport. It panics on a duplicate name, because that can
// only be a programming error and would otherwise silently shadow a connector.
func Register(name string, f Factory) {
	if _, dup := registry[name]; dup {
		panic("target: duplicate connector " + name)
	}
	registry[name] = f
}

// New builds the transport called name.
func New(name string, cfg Config) (Target, error) {
	f, ok := registry[name]
	if !ok {
		return nil, &UnknownConnectorError{Name: name, Known: Names()}
	}
	return f(cfg)
}

// Names lists the registered transports, sorted.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sortStrings(out)
	return out
}
