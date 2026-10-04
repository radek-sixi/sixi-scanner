// Command techdump exports the built-in technique set.
//
// The technique set is data — plain definitions with payloads and success
// markers — so it should be readable and diffable outside this binary. This
// command makes that concrete: it writes the catalogue as JSON or as Go
// literals, deterministically, so two dumps of the same commit are byte
// identical and a diff between them shows exactly what changed.
//
// It exists because the technique set is the part of a scanner that community
// contributions actually change. The engine is code and should be reviewed as
// code; the techniques are content and should be diffable as content.
//
//	techdump                      # JSON to stdout
//	techdump --format go          # Go literals, ready to paste
//	techdump --only probe.llm02.system-prompt-leak,probe.llm06.tool-enumeration
//	techdump --tag prompt-injection
//	techdump --compare old.json   # what changed since the last dump
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rbrus/sixi-scanner/internal/tech"
	"github.com/rbrus/sixi-scanner/internal/tech/baseline"
)

// schemaVersion is bumped when the JSON shape changes incompatibly. It is the
// same string the scan report uses, because both describe this tool's data.
const schemaVersion = "1.0"

// record is one technique as exported.
//
// It is a flat, explicit copy of tech.Definition rather than the struct itself.
// The point of an interchange format is that it can survive the source struct
// being renamed or reshaped; mirroring the Go field names exactly would tie the
// file to a version of the code and defeat that.
type record struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
	Variants    []string `json:"variants"`
	Markers     []string `json:"markers"`
	Negations   []string `json:"negations,omitempty"`
	MinMarkers  int      `json:"min_markers"`
	Confidence  float64  `json:"confidence"`
	Tags        []string `json:"tags,omitempty"`
}

// dump is the whole export.
type dump struct {
	SchemaVersion string   `json:"schema_version"`
	Tool          string   `json:"tool"`
	Count         int      `json:"count"`
	Techniques    []record `json:"techniques"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "techdump: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("techdump", flag.ContinueOnError)

	format := fs.String("format", "json", "output format: json, or go for Go literals")
	only := fs.String("only", "", "comma-separated technique IDs to export; default is all")
	tag := fs.String("tag", "", "comma-separated tags; only techniques carrying all of them")
	minSeverity := fs.String("min-severity", "", "skip techniques below this severity")
	compare := fs.String("compare", "", "path to an earlier JSON dump; report what changed")

	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: techdump [flags]

Exports the built-in technique set as data. Deterministic: the same catalogue
always produces byte-identical output, so a diff between two runs shows exactly
what a change did.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return err
	}

	reg, err := selectTechniques(splitList(*only), *tag)
	if err != nil {
		return err
	}
	if *minSeverity != "" {
		reg, err = filterSeverity(reg, *minSeverity)
		if err != nil {
			return err
		}
	}

	records := collect(reg)

	if *compare != "" {
		return report(*compare, records)
	}

	switch strings.ToLower(*format) {
	case "json":
		return writeJSON(records)
	case "go":
		return writeGo(records)
	default:
		return fmt.Errorf("unknown format %q; use json or go", *format)
	}
}

// collect turns the registry into export records, sorted by ID.
//
// Sorting is the whole reason the output is diffable. Registry order is
// insertion order, which changes whenever anyone adds a technique anywhere, so a
// plain dump of it would show a whole-file diff for a one-technique change.
func collect(reg *tech.Registry) []record {
	out := make([]record, 0, reg.Len())
	for _, t := range reg.All() {
		d := t.Meta()
		out = append(out, record{
			ID: d.ID, Title: d.Title, Category: d.Category,
			Severity: string(d.Severity), Description: d.Description,
			Remediation: d.Remediation,
			Variants:    append([]string(nil), d.Variants...),
			Markers:     append([]string(nil), d.Markers...),
			Negations:   append([]string(nil), d.Negations...),
			MinMarkers:  d.Minimum(), Confidence: d.Confidence(),
			Tags: append([]string(nil), d.Tags...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func writeJSON(records []record) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	// Payloads contain angle brackets and ampersands by design — they are
	// injection attempts. Escaping them would make the dump unreadable as the
	// thing it is for.
	enc.SetEscapeHTML(false)
	return enc.Encode(dump{
		SchemaVersion: schemaVersion,
		Tool:          "sixi-scanner",
		Count:         len(records),
		Techniques:    records,
	})
}

// writeGo emits Go literals keyed by the same field names as tech.Definition.
//
// It is deliberately a faithful mirror rather than something clever: the point
// is that a human can read the output, check it against the definitions, and
// paste it. Anything smarter would be harder to verify by eye, which defeats the
// purpose of exporting.
func writeGo(records []record) error {
	var b strings.Builder

	b.WriteString("// GENERATED by sixi-scanner techdump. Do not edit by hand.\n")
	b.WriteString("//\n")
	b.WriteString("// Exported technique data, schema version " + schemaVersion + ". Regenerate with:\n")
	b.WriteString("//\n")
	b.WriteString("//\ttechdump --format go\n")
	b.WriteString("//\n")
	b.WriteString("// The payloads below are adversarial prompts. They are inert as text and are only\n")
	b.WriteString("// dangerous when sent to an endpoint you are not authorised to test.\n\n")
	b.WriteString("package technique\n\n")
	b.WriteString("var CommunityTechniques = []Definition{\n")

	for _, r := range records {
		fmt.Fprintf(&b, "\t{\n")
		fmt.Fprintf(&b, "\t\tID:          %s,\n", quote(r.ID))
		fmt.Fprintf(&b, "\t\tTitle:       %s,\n", quote(r.Title))
		fmt.Fprintf(&b, "\t\tCategory:    %s,\n", quote(r.Category))
		fmt.Fprintf(&b, "\t\tSeverity:    Severity(%s),\n", quote(r.Severity))
		fmt.Fprintf(&b, "\t\tDescription: %s,\n", quote(r.Description))
		if r.Remediation != "" {
			fmt.Fprintf(&b, "\t\tRemediation: %s,\n", quote(r.Remediation))
		}
		fmt.Fprintf(&b, "\t\tVariants:    []string{%s},\n", quoteAll(r.Variants))
		fmt.Fprintf(&b, "\t\tMarkers:     []string{%s},\n", quoteAll(r.Markers))
		if len(r.Negations) > 0 {
			fmt.Fprintf(&b, "\t\tNegations:   []string{%s},\n", quoteAll(r.Negations))
		}
		if r.MinMarkers != 1 {
			fmt.Fprintf(&b, "\t\tMinMarkers:  %d,\n", r.MinMarkers)
		}
		if r.Confidence != 0.5 {
			fmt.Fprintf(&b, "\t\tBaseConfidence: %s,\n", trimFloat(r.Confidence))
		}
		if len(r.Tags) > 0 {
			fmt.Fprintf(&b, "\t\tTags:        []string{%s},\n", quoteAll(r.Tags))
		}
		fmt.Fprintf(&b, "\t},\n")
	}

	b.WriteString("}\n")
	fmt.Fprint(os.Stdout, b.String())
	return nil
}

// report compares this run against an earlier dump and prints what changed.
//
// This is the question that matters once the technique set has contributors:
// not "is the catalogue big" but "what did the last release add, and did
// anything disappear". A technique that vanishes silently is the failure mode
// that would not show up in a size check.
func report(path string, current []record) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	var previous dump
	if err := json.Unmarshal(raw, &previous); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	before := map[string]record{}
	for _, r := range previous.Techniques {
		before[r.ID] = r
	}
	after := map[string]record{}
	for _, r := range current {
		after[r.ID] = r
	}

	var added, removed, changed []string
	for id, r := range after {
		old, existed := before[id]
		switch {
		case !existed:
			added = append(added, id)
		case !unchanged(old, r):
			changed = append(changed, id)
		}
	}
	for id := range before {
		if _, still := after[id]; !still {
			removed = append(removed, id)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)

	fmt.Printf("before: %d techniques\n", len(previous.Techniques))
	fmt.Printf("after:  %d techniques\n\n", len(current))

	for _, id := range added {
		fmt.Printf("  added    %s  (%s)\n", id, after[id].Severity)
	}
	for _, id := range removed {
		fmt.Printf("  removed  %s\n", id)
	}
	for _, id := range changed {
		fmt.Printf("  changed  %s  %s\n", id, describeChange(before[id], after[id]))
	}

	if len(added)+len(removed)+len(changed) == 0 {
		fmt.Println("  no changes")
	}

	if len(removed) > 0 {
		fmt.Printf("\n%d technique(s) disappeared. If that was not deliberate, it is a\n", len(removed))
		fmt.Println("regression, not a diff to accept.")
	}
	return nil
}

// unchanged compares the fields that change how a technique behaves. Description
// and remediation text are excluded on purpose: rewording prose is not a
// behavioural change and flagging it would train reviewers to ignore the output.
func unchanged(a, b record) bool {
	return a.Title == b.Title &&
		a.Category == b.Category &&
		a.Severity == b.Severity &&
		a.MinMarkers == b.MinMarkers &&
		a.Confidence == b.Confidence &&
		equalStrings(a.Variants, b.Variants) &&
		equalStrings(a.Markers, b.Markers) &&
		equalStrings(a.Negations, b.Negations)
}

func describeChange(a, b record) string {
	var parts []string
	if !equalStrings(a.Variants, b.Variants) {
		parts = append(parts, fmt.Sprintf("%d→%d payloads", len(a.Variants), len(b.Variants)))
	}
	if !equalStrings(a.Markers, b.Markers) {
		parts = append(parts, "markers")
	}
	if !equalStrings(a.Negations, b.Negations) {
		parts = append(parts, "negations")
	}
	if a.MinMarkers != b.MinMarkers {
		parts = append(parts, fmt.Sprintf("min %d→%d", a.MinMarkers, b.MinMarkers))
	}
	if a.Severity != b.Severity {
		parts = append(parts, fmt.Sprintf("severity %s→%s", a.Severity, b.Severity))
	}
	if a.Confidence != b.Confidence {
		parts = append(parts, "confidence")
	}
	if len(parts) == 0 {
		return "text only"
	}
	return strings.Join(parts, ", ")
}

func selectTechniques(only []string, tag string) (*tech.Registry, error) {
	reg := baseline.Registry()

	if len(only) > 0 {
		var err error
		if reg, err = reg.Select(only); err != nil {
			return nil, err
		}
	}
	if tag != "" {
		reg = reg.SelectMatching(splitList(tag))
		if reg.Len() == 0 {
			return nil, fmt.Errorf("no technique carries all of the tags %q", tag)
		}
	}
	return reg, nil
}

func filterSeverity(reg *tech.Registry, floor string) (*tech.Registry, error) {
	min, ok := tech.ParseSeverity(floor)
	if !ok {
		return nil, fmt.Errorf("unknown severity %q", floor)
	}
	out := tech.NewRegistry()
	for _, t := range reg.All() {
		if t.Meta().Severity.AtLeast(min) {
			out.MustAdd(t)
		}
	}
	return out, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// quote emits a Go string literal. %q would almost do, but it escapes
// non-ASCII into \u sequences, and several payloads deliberately contain German
// and French text. Readable output beats canonical output for a file a human has
// to review.
func quote(s string) string {
	return `"` + strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		"\n", `\n`,
		"\t", `\t`,
		"\r", `\r`,
	).Replace(s) + `"`
}

func quoteAll(ss []string) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, quote(s))
	}
	return strings.Join(out, ", ")
}

// trimFloat prints the shortest form that still round-trips, so 0.65 does not
// become 0.65000000000000002 in a file someone has to read.
func trimFloat(f float64) string {
	s := fmt.Sprintf("%g", f)
	if !strings.ContainsAny(s, ".eE") {
		s += ".0"
	}
	return s
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
