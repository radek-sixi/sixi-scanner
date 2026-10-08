package target

import (
	"encoding/json"
	"strings"
)

// ExtractToolCalls pulls the calls out of an OpenAI-shaped message, and reports whether the trace
// could be read at all.
//
// The second return value is the one that matters. A reply with no tool calls and a connector that
// cannot see tool calls look identical if both collapse to nil, and conflating them makes every
// trace-based check inert exactly where it is needed: an agent that called nothing and said it had
// sent something. So "the message was OpenAI-shaped and listed no calls" returns an empty non-nil
// slice with known=true, and only a message we could not read at all returns known=false.
//
// It is also deliberately forgiving about shape: an agent that emits a malformed call has still
// emitted one, and dropping it would turn a detected claim into a missed finding.
func ExtractToolCalls(msg any) ([]ToolCall, bool) {
	obj, ok := msg.(map[string]any)
	if !ok {
		return nil, false
	}
	raw, present := obj["tool_calls"]
	if !present {
		// No tool_calls key at all. That is NOT the same as an empty list: it means this endpoint
		// does not report a trace, and the agent may well have called anything. Returning
		// "known, empty" here is how a scanner ends up declaring lies it has no evidence for --
		// measured against a live gateway that returns only {role, content} while the agent behind
		// it called lookup_account then send_email. Fourteen confident false accusations came out of
		// this one line.
		return nil, false
	}
	rawList, ok := raw.([]any)
	if !ok || len(rawList) == 0 {
		// The key is present and empty: the endpoint does report a trace, and the agent called
		// nothing. That is a fact about the turn.
		return []ToolCall{}, true
	}
	out := make([]ToolCall, 0, len(rawList))
	for _, r := range rawList {
		entry, ok := r.(map[string]any)
		if !ok {
			continue
		}
		fn, _ := entry["function"].(map[string]any)
		name, _ := fn["name"].(string)
		if name == "" {
			name, _ = entry["name"].(string)
		}
		if name == "" {
			continue
		}
		args := ""
		switch a := fn["arguments"].(type) {
		case string:
			args = a
		default:
			if a != nil {
				if b, mErr := json.Marshal(a); mErr == nil {
					args = string(b)
				}
			}
		}
		out = append(out, ToolCall{Name: name, Args: args})
	}
	return out, true
}

// digAny walks a dotted path and returns the value found there, without insisting it is a string.
// dig returns only leaves it can render as text, which is no use for a tool-call object.
func digAny(v any, path string) any {
	if path == "" {
		return nil
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil
			}
			cur = next
		case []any:
			i, err := atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return nil
			}
			cur = node[i]
		default:
			return nil
		}
	}
	return cur
}
