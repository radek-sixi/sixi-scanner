package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON writes the scan as indented JSON.
//
// Durations are emitted as integer milliseconds by the struct tags, which is
// what a CI job or a dashboard wants; there is no duration string to parse.
func WriteJSON(w io.Writer, s *Scan) error {
	s.Summarise()

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// HTML escaping would turn < and > in an attacker's payload into &lt;
	// and &gt;, which corrupts the evidence a reader needs to verify a
	// finding. A report is not HTML.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return fmt.Errorf("write JSON: %w", err)
	}
	return nil
}
