package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rbrus/sixi-scanner/internal/report"
	"github.com/rbrus/sixi-scanner/internal/tech"
	"github.com/rbrus/sixi-scanner/internal/tech/baseline"
)

func cmdList(args []string, stdout io.Writer) result {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "emit the technique catalogue as JSON")
	detail := fs.String("detail", "", "print one technique in full, by ID")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, `Usage: sixi-scanner list [flags]

Lists the built-in technique set. With --detail, prints one technique in full.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return result{code: exitUsage, err: err}
	}

	reg := baseline.Registry()

	if *detail != "" {
		t, ok := reg.Get(*detail)
		if !ok {
			return result{code: exitUsage, err: fmt.Errorf("unknown technique %q; run \"sixi-scanner list\" for the catalogue", *detail)}
		}
		return succeeded(printDetail(stdout, t.Meta()))
	}

	if *asJSON {
		return succeeded(printCatalogueJSON(stdout, reg))
	}

	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSEVERITY\tCATEGORY\tTITLE")
	for _, t := range reg.All() {
		d := t.Meta()
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", d.ID, d.Severity, d.Category, d.Title)
	}
	if err := w.Flush(); err != nil {
		return result{code: exitUsage, err: err}
	}

	fmt.Fprintf(stdout, "\n%d techniques. Detail: sixi-scanner list --detail <ID>\n", reg.Len())
	fmt.Fprintln(stdout, "This is a baseline set of publicly documented attacks. A clean result is")
	fmt.Fprintln(stdout, "not an assurance. See docs/techniques.md for what is and is not covered.")
	return succeeded(nil)
}

type catalogueEntry struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
	Variants    int      `json:"variant_count"`
	Markers     int      `json:"marker_count"`
	MinMarkers  int      `json:"min_markers"`
}

func printCatalogueJSON(w io.Writer, reg *tech.Registry) error {
	entries := make([]catalogueEntry, 0, reg.Len())
	for _, t := range reg.All() {
		d := t.Meta()
		entries = append(entries, catalogueEntry{
			ID: d.ID, Title: d.Title, Category: d.Category,
			Severity: string(d.Severity), Tags: d.Tags,
			Description: d.Description, Remediation: d.Remediation,
			Variants: len(d.Variants), Markers: len(d.Markers),
			MinMarkers: d.Minimum(),
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]any{
		"schema_version": report.SchemaVersion,
		"count":          len(entries),
		"techniques":     entries,
	}); err != nil {
		return err
	}
	return nil
}

func printDetail(w io.Writer, d tech.Definition) error {
	fmt.Fprintf(w, "%s\n", d.Title)
	fmt.Fprintf(w, "%s\n\n", strings.Repeat("=", len(d.Title)))
	fmt.Fprintf(w, "ID          %s\n", d.ID)
	fmt.Fprintf(w, "Severity    %s\n", d.Severity)
	fmt.Fprintf(w, "Category    %s\n", d.Category)
	if len(d.Tags) > 0 {
		fmt.Fprintf(w, "Tags        %s\n", strings.Join(d.Tags, ", "))
	}
	fmt.Fprintf(w, "\n%s\n\n", d.Description)
	if d.Remediation != "" {
		fmt.Fprintf(w, "Remediation\n  %s\n\n", d.Remediation)
	}

	fmt.Fprintf(w, "Variants (%d)\n", len(d.Variants))
	for i, v := range d.Variants {
		fmt.Fprintf(w, "  %d. %s\n", i+1, oneLine(v))
	}
	fmt.Fprintf(w, "\nSuccess markers (%d, minimum %d)\n", len(d.Markers), d.Minimum())
	for _, m := range d.Markers {
		fmt.Fprintf(w, "  - %q\n", m)
	}
	if len(d.Negations) > 0 {
		fmt.Fprintf(w, "\nNegation cues (%d)\n", len(d.Negations))
		for _, n := range d.Negations {
			fmt.Fprintf(w, "  - %q\n", n)
		}
	}
	fmt.Fprintf(w, "\nRe-run just this one:\n  sixi-scanner scan --only %s --url <endpoint>\n", d.ID)
	return nil
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	return strings.Join(strings.Fields(s), " ")
}

var _ = time.Second
