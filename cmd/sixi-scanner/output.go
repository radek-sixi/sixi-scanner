package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rbrus/sixi-scanner/internal/report"
)

// writeReport renders the scan in the chosen format. For text, findings are
// printed to stderr and only the summary goes to stdout, so
// `sixi-scanner scan ... > summary.txt` captures a clean artefact.
func writeReport(w io.Writer, format string, scan *report.Scan, findingsToStderr bool) error {
	switch strings.ToLower(format) {
	case "json":
		return report.WriteJSON(w, scan)
	case "sarif":
		return report.WriteSARIF(w, scan)
	case "markdown", "md":
		return report.WriteMarkdown(w, scan)
	case "text", "":
		return writeText(w, scan, findingsToStderr)
	default:
		return fmt.Errorf("unknown format %q; use text, json, sarif or markdown", format)
	}
}

func writeText(w io.Writer, scan *report.Scan, toStderr bool) error {
	out := w
	if toStderr {
		out = os.Stderr
		writeFindingsTo(out, scan)
	}
	_, err := fmt.Fprintf(w, "%s\n", scan.String())
	return err
}

func writeFindingsTo(w io.Writer, scan *report.Scan) {
	if len(scan.NoAnswer) > 0 {
		fmt.Fprintf(w, "\nNot tested (no answer from the target):\n")
		for _, id := range scan.NoAnswer {
			fmt.Fprintf(w, "  - %s\n", id)
		}
	}
	// Kept separate from the list above: a technique here was never sent, not sent-and-ignored. The
	// distinction is the difference between "we asked and it held" and "we could not ask".
	if len(scan.Unsupported) > 0 {
		fmt.Fprintf(w, "\nNot tested (this target cannot run them):\n")
		for _, u := range scan.Unsupported {
			fmt.Fprintf(w, "  - %s: %s\n", u.TechniqueID, u.Reason)
		}
	}
	if len(scan.Findings) == 0 {
		return
	}

	fmt.Fprintf(w, "\n%d finding(s)\n\n", len(scan.Findings))
	for i, f := range scan.Findings {
		fmt.Fprintf(w, "%d. [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.Title)
		fmt.Fprintf(w, "   %s  confidence %.2f  %s\n", f.TechniqueID, f.Confidence, f.Evidence.Reason)
		fmt.Fprintf(w, "   prompt:  %s\n", excerpt(f.Evidence.Prompt, 160))
		fmt.Fprintf(w, "   reply:   %s\n\n", excerpt(f.Evidence.Response, 160))
	}
}

// writeFile writes the report to a path, creating parent directories, and
// infers the format from the extension when --format was left at text.
func writeFile(path, format string, scan *report.Scan) error {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	effective := strings.ToLower(format)
	if effective == "text" || effective == "" {
		if effective = formatFromExt(path); effective == "" {
			effective = "json"
		}
	}
	if err := writeReport(f, effective, scan, false); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func formatFromExt(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "json"
	case ".sarif":
		return "sarif"
	case ".md", ".markdown":
		return "markdown"
	default:
		return ""
	}
}

func excerpt(s string, n int) string {
	s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
